const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

// ===============================
// APP INITIALIZATION
// ===============================
const app = express();
const port = process.env.PORT || 3000;

// ===============================
// SECURITY MIDDLEWARES
// ===============================
app.use(helmet());
app.use(cookieParser());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});
app.use(limiter);

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((origin) => origin.trim())
  : ["http://localhost:5173", "http://localhost:3000"];

app.use(
  cors({
    origin: (origin, callback) => {
      // allow no-origin requests (Postman, mobile apps)
      if (!origin || allowedOrigins.includes(origin)) callback(null, true);
      else callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "10kb" }));

// ===============================
// ASYNC HANDLER WRAPPER
// ===============================
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ===============================
// CONSTANTS + HELPERS
// ===============================
const VALID_ROLES = ["customer", "staff", "admin"];
const normalizeEmail = (email) => (email || "").toLowerCase().trim();

const isProd = process.env.NODE_ENV === "production";
const cookieSecure = process.env.COOKIE_SECURE === "true" || isProd;

// refresh cookie only used for refresh endpoint
const refreshCookieOptions = {
  httpOnly: true,
  secure: cookieSecure,                      // prod must be true (HTTPS)
  sameSite: cookieSecure ? "none" : "lax",   // lax for dev (avoids cookie block)
  path: "/api/auth/refresh",
};

// ===============================
// JWT (Access + Refresh)
// ===============================
const signAccessToken = (payload) => {
  if (!process.env.JWT_ACCESS_SECRET) throw new Error("JWT_ACCESS_SECRET missing");
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
  });
};

const signRefreshToken = (payload) => {
  if (!process.env.JWT_REFRESH_SECRET) throw new Error("JWT_REFRESH_SECRET missing");
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "30d",
  });
};

const verifyAccessToken = (token) => jwt.verify(token, process.env.JWT_ACCESS_SECRET);
const verifyRefreshToken = (token) => jwt.verify(token, process.env.JWT_REFRESH_SECRET);

const hashToken = (token) => bcrypt.hash(token, 12);
const compareToken = (token, hash) => bcrypt.compare(token, hash);

// ===============================
// AUTH MIDDLEWARES
// ===============================
const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing access token" });
  }

  const token = authHeader.split("Bearer ")[1];

  try {
    const decoded = verifyAccessToken(token);
    req.user = { uid: decoded.uid, email: decoded.email || null };
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }
};

const loadUserRole = (usersCollection) => {
  return async (req, res, next) => {
    try {
      const user =
        (await usersCollection.findOne({ uid: req.user.uid })) ||
        (ObjectId.isValid(req.user.uid)
          ? await usersCollection.findOne({ _id: new ObjectId(req.user.uid) })
          : null);

      if (!user) {
        return res.status(403).json({ error: "User not found" });
      }

      req.user.role = user.role;
      req.user.dbUser = user;
      next();
    } catch (error) {
      console.error("Load user role error:", error.message);
      return res.status(500).json({ error: "Internal server error" });
    }
  };
};

const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user?.role) return res.status(403).json({ error: "Role not loaded" });

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Forbidden",
        message: `Required role: ${allowedRoles.join(" or ")}. Your role: ${req.user.role}`,
      });
    }
    next();
  };
};

// ===============================
// MONGODB CONNECTION
// ===============================
const client = new MongoClient(process.env.MONGODB_URI);

async function startServer() {
  try {
    await client.connect();

    const db = client.db("cafe_billing");
    const itemsCollection = db.collection("all_items");
    const usersCollection = db.collection("users");
    const auditsCollection = db.collection("audits");

    // Indexes (named => no conflict)
    await usersCollection.createIndex({ email: 1 }, { unique: true, name: "email_unique" });
    await usersCollection.createIndex({ uid: 1 }, { unique: true, sparse: true, name: "uid_unique_sparse" });
    await auditsCollection.createIndex({ createdAt: -1 });
    await auditsCollection.createIndex({ targetUid: 1 });

    console.log("✅ MongoDB Connected");

    // ===============================
    // ROOT
    // ===============================
    app.get("/", (req, res) => {
      res.json({ message: "Cafe Billing API Running", status: "healthy", version: "2.0.0" });
    });

    // ===============================
    // AUTH ROUTES (PROFESSIONAL)
    // ===============================

    // Register -> returns accessToken + sets refresh cookie
    app.post(
      "/api/auth/register",
      asyncHandler(async (req, res) => {
        const email = normalizeEmail(req.body.email);
        const { name, password } = req.body;

        if (!name || !name.trim()) {
          return res.status(400).json({ error: "Name is required" });
        }

        if (!email || !password || password.length < 6) {
          return res.status(400).json({ error: "Email and password (min 6 chars) required" });
        }

        const existing = await usersCollection.findOne({ email });
        if (existing) return res.status(409).json({ error: "Email already registered" });

        const now = new Date();
        const passwordHash = await bcrypt.hash(password, 12);

        const result = await usersCollection.insertOne({
          name,
          email,
          passwordHash,
          role: "customer",
          refreshTokenHash: null,
          createdAt: now,
          updatedAt: now,
        });

        const uid = result.insertedId.toString();
        await usersCollection.updateOne({ _id: result.insertedId }, { $set: { uid } });

        const accessToken = signAccessToken({ uid, email });
        const refreshToken = signRefreshToken({ uid, email });

        await usersCollection.updateOne(
          { _id: result.insertedId },
          { $set: { refreshTokenHash: await hashToken(refreshToken), updatedAt: new Date() } }
        );

        res.cookie("refreshToken", refreshToken, refreshCookieOptions);

        res.status(201).json({
          success: true,
          accessToken,
          user: { uid, email, role: "customer" },
        });
      })
    );

    // Login -> returns accessToken + sets refresh cookie
    app.post(
      "/api/auth/login",
      asyncHandler(async (req, res) => {
        const email = normalizeEmail(req.body.email);
        const { password } = req.body;

        if (!email || !password) {
          return res.status(400).json({ error: "Email and password required" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(401).json({ error: "Invalid credentials" });

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ error: "Invalid credentials" });

        const uid = user.uid || user._id.toString();

        const accessToken = signAccessToken({ uid, email: user.email });
        const refreshToken = signRefreshToken({ uid, email: user.email });

        await usersCollection.updateOne(
          { _id: user._id },
          { $set: { refreshTokenHash: await hashToken(refreshToken), updatedAt: new Date() } }
        );

        res.cookie("refreshToken", refreshToken, refreshCookieOptions);

        res.json({
          success: true,
          accessToken,
          user: { uid, email: user.email, role: user.role },
        });
      })
    );

    // Refresh -> reads refresh cookie, rotates refresh, returns new access token
    app.post(
      "/api/auth/refresh",
      asyncHandler(async (req, res) => {
        const token = req.cookies?.refreshToken;
        if (!token) return res.status(401).json({ error: "Missing refresh token" });

        let decoded;
        try {
          decoded = verifyRefreshToken(token);
        } catch {
          return res.status(401).json({ error: "Invalid refresh token" });
        }

        const uid = decoded.uid;

        const user =
          (await usersCollection.findOne({ uid })) ||
          (ObjectId.isValid(uid) ? await usersCollection.findOne({ _id: new ObjectId(uid) }) : null);

        if (!user || !user.refreshTokenHash) {
          return res.status(401).json({ error: "Refresh token not recognized" });
        }

        const ok = await compareToken(token, user.refreshTokenHash);
        if (!ok) return res.status(401).json({ error: "Refresh token mismatch" });

        // ROTATE refresh token (professional)
        const newAccessToken = signAccessToken({ uid: user.uid, email: user.email });
        const newRefreshToken = signRefreshToken({ uid: user.uid, email: user.email });

        await usersCollection.updateOne(
          { _id: user._id },
          { $set: { refreshTokenHash: await hashToken(newRefreshToken), updatedAt: new Date() } }
        );

        res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);

        res.json({ success: true, accessToken: newAccessToken });
      })
    );

    // Logout -> clears refresh cookie + revokes refresh in DB
    app.post(
      "/api/auth/logout",
      asyncHandler(async (req, res) => {
        const token = req.cookies?.refreshToken;

        if (token) {
          try {
            const decoded = verifyRefreshToken(token);
            await usersCollection.updateOne(
              { uid: decoded.uid },
              { $set: { refreshTokenHash: null, updatedAt: new Date() } }
            );
          } catch {
            // ignore
          }
        }

        res.clearCookie("refreshToken", refreshCookieOptions);
        res.json({ success: true, message: "Logged out" });
      })
    );

    // Me -> protected by access token
    app.get(
      "/api/auth/me",
      requireAuth,
      loadUserRole(usersCollection),
      asyncHandler(async (req, res) => {
        res.json({
          uid: req.user.dbUser.uid || req.user.dbUser._id.toString(),
          email: req.user.dbUser.email,
          role: req.user.dbUser.role,
        });
      })
    );

    // ===============================
    // ADMIN BOOTSTRAP (optional)
    // ===============================
    app.post(
      "/api/bootstrap/admin",
      asyncHandler(async (req, res) => {
        if (process.env.ENABLE_ADMIN_BOOTSTRAP !== "true") {
          return res.status(403).json({ error: "Admin bootstrap is disabled" });
        }

        const { secret } = req.body;
        const email = normalizeEmail(req.body.email);

        if (!secret || secret !== process.env.ADMIN_BOOTSTRAP_SECRET) {
          return res.status(401).json({ error: "Invalid bootstrap secret" });
        }

        if (!email || email !== normalizeEmail(process.env.ADMIN_BOOTSTRAP_EMAIL)) {
          return res.status(403).json({ error: "Email not authorized for admin bootstrap" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found. Register first." });

        const now = new Date();
        const oldRole = user.role;

        await usersCollection.updateOne(
          { _id: user._id },
          { $set: { role: "admin", updatedAt: now } }
        );

        await auditsCollection.insertOne({
          action: "BOOTSTRAP_ADMIN",
          actorUid: null,
          targetUid: user.uid || user._id.toString(),
          meta: { fromRole: oldRole, toRole: "admin", email: user.email },
          createdAt: now,
        });

        res.json({
          success: true,
          message: "Admin role assigned successfully",
          warning: "IMPORTANT: Set ENABLE_ADMIN_BOOTSTRAP=false in production!",
        });
      })
    );

    // ===============================
    // USER MANAGEMENT ROUTES (ADMIN)
    // ===============================
    app.patch(
      "/api/users/:uid/role",
      requireAuth,
      loadUserRole(usersCollection),
      requireRole("admin"),
      asyncHandler(async (req, res) => {
        const { uid: targetUid } = req.params;
        const { role: newRole } = req.body;

        if (!newRole || !VALID_ROLES.includes(newRole)) {
          return res.status(400).json({ error: `Role must be one of: ${VALID_ROLES.join(", ")}` });
        }

        const targetUser =
          (await usersCollection.findOne({ uid: targetUid })) ||
          (ObjectId.isValid(targetUid)
            ? await usersCollection.findOne({ _id: new ObjectId(targetUid) })
            : null);

        if (!targetUser) return res.status(404).json({ error: "User not found" });

        const now = new Date();
        const oldRole = targetUser.role;

        await usersCollection.updateOne(
          { _id: targetUser._id },
          { $set: { role: newRole, updatedAt: now } }
        );

        await auditsCollection.insertOne({
          action: "CHANGE_ROLE",
          actorUid: req.user.uid,
          targetUid: targetUser.uid || targetUser._id.toString(),
          meta: { fromRole: oldRole, toRole: newRole, email: targetUser.email },
          createdAt: now,
        });

        res.json({
          success: true,
          uid: targetUser.uid || targetUser._id.toString(),
          previousRole: oldRole,
          role: newRole,
        });
      })
    );

    app.get(
      "/api/users",
      requireAuth,
      loadUserRole(usersCollection),
      requireRole("admin"),
      asyncHandler(async (req, res) => {
        const users = await usersCollection
          .find({}, { projection: { _id: 0, uid: 1, email: 1, role: 1, createdAt: 1 } })
          .sort({ createdAt: -1 })
          .toArray();

        res.json(users);
      })
    );

    app.get(
      "/api/audits",
      requireAuth,
      loadUserRole(usersCollection),
      requireRole("admin"),
      asyncHandler(async (req, res) => {
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const audits = await auditsCollection.find({}).sort({ createdAt: -1 }).limit(limit).toArray();
        res.json(audits);
      })
    );

    // ===============================
    // ITEMS ROUTES (PUBLIC + ADMIN CRUD)
    // ===============================
    app.get(
      "/api/all_items",
      asyncHandler(async (req, res) => {
        const items = await itemsCollection.find().toArray();
        res.json(items);
      })
    );

    app.post(
      "/api/items",
      requireAuth,
      loadUserRole(usersCollection),
      requireRole("admin"),
      asyncHandler(async (req, res) => {
        const { name, price, category, description, available } = req.body;

        if (!name || price === undefined) {
          return res.status(400).json({ error: "Name and price are required" });
        }

        const now = new Date();
        const newItem = {
          name: name.trim(),
          price: parseFloat(price),
          category: category?.trim() || "Uncategorized",
          description: description?.trim() || "",
          available: available !== false,
          createdAt: now,
          updatedAt: now,
        };

        const result = await itemsCollection.insertOne(newItem);
        res.status(201).json({ success: true, item: { _id: result.insertedId, ...newItem } });
      })
    );

    app.patch(
      "/api/items/:id",
      requireAuth,
      loadUserRole(usersCollection),
      requireRole("admin"),
      asyncHandler(async (req, res) => {
        const { id } = req.params;
        const updates = req.body;

        if (!ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid item ID" });

        const allowedFields = ["name", "price", "category", "description", "available"];
        const updateData = { updatedAt: new Date() };

        for (const field of allowedFields) {
          if (updates[field] !== undefined) {
            if (field === "price") updateData[field] = parseFloat(updates[field]);
            else if (field === "name" || field === "category" || field === "description")
              updateData[field] = updates[field]?.trim();
            else updateData[field] = updates[field];
          }
        }

        const result = await itemsCollection.findOneAndUpdate(
          { _id: new ObjectId(id) },
          { $set: updateData },
          { returnDocument: "after" }
        );

        if (!result) return res.status(404).json({ error: "Item not found" });
        res.json({ success: true, item: result });
      })
    );

    app.delete(
      "/api/items/:id",
      requireAuth,
      loadUserRole(usersCollection),
      requireRole("admin"),
      asyncHandler(async (req, res) => {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid item ID" });

        const result = await itemsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Item not found" });

        res.json({ success: true, message: "Item deleted" });
      })
    );

    // ===============================
    // 404 HANDLER
    // ===============================
    app.use((req, res) => res.status(404).json({ error: "Route not found" }));

    // ===============================
    // GLOBAL ERROR HANDLER
    // ===============================
    app.use((err, req, res, next) => {
      console.error("Error:", err.message);

      if (err.message === "Not allowed by CORS") {
        return res.status(403).json({ error: "CORS policy violation" });
      }

      if (err.code === 11000) {
        return res.status(409).json({ error: "Duplicate entry" });
      }

      res.status(err.status || 500).json({
        error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
      });
    });

    // ===============================
    // START SERVER
    // ===============================
    app.listen(port, () => {
      console.log(`✅ Server running on port ${port}`);
      console.log(`📍 Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(`🌐 CORS: ${allowedOrigins.join(", ")}`);
      console.log(`🍪 Refresh cookie secure: ${cookieSecure ? "YES" : "NO (dev)"}`);
    });

    process.on("SIGINT", async () => {
      console.log("\n🛑 Shutting down gracefully...");
      await client.close();
      process.exit(0);
    });
  } catch (error) {
    console.error("❌ Server startup failed:", error.message);
    process.exit(1);
  }
}

startServer();

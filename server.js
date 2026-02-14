const express = require("express");
const cors = require("cors");
const { MongoClient } = require("mongodb");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const client = new MongoClient(process.env.MONGODB_URI);

async function startServer() {
  try {
    await client.connect();

    const db = client.db("cafe_billing");
    const itemsCollection = db.collection("all_items");

    console.log("✅ MongoDB Connected");

    // Root
    app.get("/", (req, res) => {
      res.send("Cafe Billing API Running ✅");
    });

    // ===============================
    // GET ALL ITEMS
    // ===============================
    app.get("/api/all_items", async (req, res) => {
      try {
        const items = await itemsCollection.find().toArray();
        res.json(items);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });



    app.listen(port, () => {
      console.log(`✅ Server running on port ${port}`);
    });

  } catch (error) {
    console.error("❌ DB Connection Failed:", error.message);
    process.exit(1);
  }
}

startServer();

// Combined Auth and Product Code
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const app = express();
const port = 3000;
app.use(express.json());

mongoose
  .connect("mongodb://localhost:27017/combined_db")
  .then(() => console.log("Database connected"))
  .catch((err) => console.log("Database connection error:", err));

// --- User Schema ---
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const Users = mongoose.model("User", userSchema);

// --- Campaign Schema ---
const campaignSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  productId: { type: String, required: true },
  name: { type: String, required: true },
  description: { type: String },
  amount: { type: Number, required: true },
  percentage: { type: String, required: true },
  createdAt: { type: Date, required: true },
  updatedAt: { type: Date, required: true },
});
const Campaign = mongoose.model("Campaign", campaignSchema);

// --- Product Schema ---
const productSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  category: { type: String, required: true, enum: ["Electronics", "Clothing", "Food"] },
  url: { type: String },
  stock: { type: String, required: true },
  size: { type: String, required: true },
  composition: { type: String, required: true },
  color: { type: String, required: true },
  weight: { type: String, required: true },
  images: { type: String, required: true },
  campaign_Id: { type: String, required: true },
  deleted: { type: Boolean, default: false },
});
const Product = mongoose.model("Product", productSchema);

// --- Register ---
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new Users({ username: req.body.username, password: hashedPassword });
    await user.save();
    res.send({ status: "Success", message: "User registered successfully" });
  } catch (error) {
    res.send({ error: "Registration failed" });
  }
});

// --- Login ---
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await Users.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send({ error: "Authentication failed" });
    }
    const token = jwt.sign({ username: user.username }, "my-secret-key", { expiresIn: "1h" });
    res.send({ status: "Success", message: "Login successful", token });
  } catch (error) {
    res.send({ error: "Login failed" });
  }
});

// --- Verify Token Middleware ---
const verifyToken = (req, res, next) => {
  const token = req.header("auth");
  if (!token) return res.send({ error: "Access denied" });
  try {
    req.user = jwt.verify(token, "my-secret-key");
    next();
  } catch (error) {
    res.send({ error: "Invalid token" });
  }
};

// --- Protected Route ---
app.get("/protected", verifyToken, (req, res) => {
  res.send({ message: "Protected route accessed" });
});

// --- Create Product with Campaign ---
app.post("/products", verifyToken, async (req, res) => {
  try {
    const { name, price, category } = req.body;
    if (!name || !price || !category) {
      return res.send({ status: "ERROR", message: "Name, price, and category are required" });
    }

    const campaign_Id = uuidv4();
    const productId = uuidv4();

    const campaign = new Campaign({
      id: campaign_Id,
      productId,
      name: req.body.campaign.name,
      description: req.body.campaign.description,
      amount: req.body.campaign.amount,
      percentage: req.body.campaign.percentage,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const product = new Product({
      id: productId,
      name,
      description: req.body.description,
      price,
      category,
      url: req.body.url,
      stock: req.body.stock,
      size: req.body.size,
      composition: req.body.composition,
      color: req.body.color,
      weight: req.body.weight,
      images: req.body.images,
      campaign_Id,
    });

    await product.save();
    await campaign.save();

    res.send({ status: "SUCCESS", message: "Product created successfully", product: { productId } });
  } catch (error) {
    res.send({ status: "ERROR", message: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
// --- Get All Products ---
app.get("/products", verifyToken, async (req, res) => {
  try {
    const products = await Product.find({ deleted: false });
    const productsWithCampaigns = await Promise.all(products.map(async (product) => {
      const campaign = await Campaign.findOne({ id: product.campaign_Id });
      return {
        ...product.toObject(),
        campaign
      };
    }));
    res.send({ status: "SUCCESS", products: productsWithCampaigns });
  } catch (error) {
    res.send({ status: "ERROR", message: error.message });
  }
});

// --- Get Single Product ---
app.get("/products/:id", verifyToken, async (req, res) => {
  try {
    const product = await Product.findOne({ id: req.params.id, deleted: false });
    if (!product) {
      return res.send({ status: "ERROR", message: "Product not found" });
    }
    const campaign = await Campaign.findOne({ id: product.campaign_Id });
    res.send({ 
      status: "SUCCESS", 
      product: {
        ...product.toObject(),
        campaign
      }
    });
  } catch (error) {
    res.send({ status: "ERROR", message: error.message });
  }
});

// --- Update Product ---
app.put("/products/:id", verifyToken, async (req, res) => {
  try {
    const { name, price, category } = req.body;
    if (!name || !price || !category) {
      return res.send({ status: "ERROR", message: "Name, price, and category are required" });
    }

    const product = await Product.findOneAndUpdate(
      { id: req.params.id },
      {
        name,
        description: req.body.description,
        price,
        category,
        url: req.body.url,
        stock: req.body.stock,
        size: req.body.size,
        composition: req.body.composition,
        color: req.body.color,
        weight: req.body.weight,
        images: req.body.images,
        updatedAt: new Date()
      },
      { new: true }
    );

    if (req.body.campaign) {
      await Campaign.findOneAndUpdate(
        { id: product.campaign_Id },
        {
          name: req.body.campaign.name,
          description: req.body.campaign.description,
          amount: req.body.campaign.amount,
          percentage: req.body.campaign.percentage,
          updatedAt: new Date()
        }
      );
    }

    res.send({ status: "SUCCESS", message: "Product updated successfully" });
  } catch (error) {
    res.send({ status: "ERROR", message: error.message });
  }
});

// --- Delete Product (Soft Delete) ---
app.delete("/products/:id", verifyToken, async (req, res) => {
  try {
    await Product.findOneAndUpdate(
      { id: req.params.id },
      { deleted: true }
    );
    res.send({ status: "SUCCESS", message: "Product deleted successfully" });
  } catch (error) {
    res.send({ status: "ERROR", message: error.message });
  }
});

const express = require("express");
const mongoose = require("mongoose");
const shop_app = express();
const port = 3000;

shop_app.use(express.json());

mongoose.connect("mongodb://localhost:27017/test")
  .then(() => console.log("Database connected"))
  .catch((e) => console.log(e));

const productSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  url: { type: String, required: true },
  stock: { type: String, required: true },
  battery_life: { type: String , required: true},
  charging_time: { type: String , required: true },
  connectivity: { type: String , required: true },
  weight: { type: String , required: true },
  images: { type: String, required: true  },
});

const Product = mongoose.model("Product", productSchema);

shop_app.post("/products", async (req, res) => {
  try {
    const product = new Product({
      id: Math.floor(Math.random() * 1000),
      name: req.body.name,
      description: req.body.description,
      price: req.body.price,
      category: req.body.category,
      url: req.body.url,
      stock: req.body.stock,
      battery_life: req.body.battery_life,
      charging_time: req.body.charging_time,
      connectivity: req.body.connectivity,
      weight: req.body.weight,
      images: req.body.images,
    });
    await product.save();
    res.send({ status: "SUCCESS",
       message: "Product added",
       data: product });
  } catch (error) {
    res.send({ status: "ERROR",
       message: error.message });
  }

});

shop_app.get("/Get_all_products", async (req, res) => {
  try {
    const products = await Product.find();
    res.send({ status: "SUCCESS",
      count: products.length, 
      data: products });
  } catch (error) {
    res.send({ status: "ERROR", 
      message: error.message });
  }
});

shop_app.post("/find_product", async (req, res) => {
  try {
    const product = await Product.findOne({ id: req.body.id });
    if (!product) {
      return res.send({ status: "FAIL", 
        message: "Product not found" });
    } else {
      res.send({ status: "SUCCESS", 
        message: "Product found", 
        data: product });
    }
  } catch (error) {
    res.send({ status: "ERROR", 
      message: error.message });
  }
});
shop_app.post("/delete-note", async (req, res) => {
  try {
    const id = req.body.id;
    const result = await Product.findOneAndDelete({ id: id });
    if (result) {
      res.send({
        status: "SUCCESS",
        message: "Note deleted successfully",
      });
    } else {
      res.send({
        status: "FAIL",
        message: "Note not found",
      });
    }
  } catch (error) {
    res.send({
      status: "ERROR",
      message: "Error deleting note",
    });
  }
});
shop_app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

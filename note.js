const express = require("express");
const mongoose = require("mongoose");
const app = express();
const port = 3000;

app.use(express.json());
mongoose
  .connect("mongodb://localhost:27017/test")
  .then(() => console.log("connected"))
  .catch((e) => console.log(e));
const contactSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, required: true },
  content: { type: String, required: true },
});
const Contact = mongoose.model("Contact", contactSchema);
app.get("/test", (req, res) => {
  res.send("API is working!");
});
app.post("/notes", async (req, res) => {
  const note1 = new Contact({
    id: Math.floor(Math.random() * 1000),
    title: req.body["title 1 "] || "Untitled",
    content: req.body.content || "No content",
  });

  console.log(note1);
  // Save note
  // db.push(note1);
  await note1.save();

  // Send response
  res.send({
    status: "SUCCESS",
    message: "Notes created",
    data: [note1],
  });
});

// Get all notes
app.get("/all-notes", (req, res) => {
  res.send({
    status: "SUCCESS",
    count: db.length,
    data: db,
  });
});
// Get note by ID
app.post("/get-note", async (req, res) => {
  // note1[];
  try {
    const note1 = await Contact.findOne({ id: req.body.id });
    console.log(note1);
    res.send({
      status: "SUCCESS",
      message: "Note deleted successfully",
      data: note1,
    });
  } catch (error) {
    console.log(error);
  }
});
// Delete note
app.post("/delete-note", async (req, res) => {
  try {
    const noteId = req.body.id;
    const result = await Contact.findOneAndDelete({ id: noteId });
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
    console.log(error);
    res.send({
      status: "ERROR",
      message: "Error deleting note",
    });
  }
});
// // Update note
// try{
//   const result = await Contact.findByIdAndUpdate( id: req.body.id,{
//     title: result.title,
//     content: result.content
app.post("/update-note", async (req, res) => {
  try {
    console.log(req.body.title);
    const idValue = req.body.id;
   if((req.body.title === undefined && req.body.title === null))

   {throw new Error("data is required")}
    
    await Contact.findOneAndUpdate(
      { id: idValue },
      {
        title: req.body.title,
        content: req.body.content,
        updatedAt: new Date(),
      }
    ).exec();
    return res.send({
      status: "success",
      message: "Note updated successfully",
   })

  } catch (error) {
    console.log(`Note not found with error - ${error.message}`);
    return res.send ({status: "fail",
      message : error.message,
  })
    
  }
});
// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

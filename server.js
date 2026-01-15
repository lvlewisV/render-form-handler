const express = require("express");
const app = express();

// Middleware to parse form data & JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Health check (important for Render)
app.get("/", (req, res) => {
  res.send("Render form handler is running");
});

// Example form endpoint
app.post("/submit", (req, res) => {
  console.log("Form submission received:", req.body);

  res.status(200).json({
    success: true,
    message: "Form received"
  });
});

// Render requires this
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

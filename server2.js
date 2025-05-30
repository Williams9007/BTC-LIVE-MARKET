require("dotenv").config();
const mongoose = require("mongoose");
const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const Joi = require("joi");
const jwt = require("jsonwebtoken"); // Install this if not already installed: npm install jsonwebtoken

const app = express();
const PORT = process.env.PORT || 5000; // Use a dynamic port if available

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Ensure MongoDB URI is loaded
if (!process.env.MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI is not set in the .env file");
  process.exit(1); // Exit the application if no MongoDB URI
}

console.log("🔗 Connecting to MongoDB...");

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("✅ MongoDB Atlas Connected"))
  .catch(err => {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1); // Exit process if connection fails
  });

// Handle MongoDB errors after initial connection
mongoose.connection.on("error", err => {
  console.error("❌ MongoDB Runtime Error:", err.message);
});

// Define a User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Create a User model
const User = mongoose.model("User", userSchema);

const registerSchema = Joi.object({
  username: Joi.string().min(3).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
});

// API endpoint to handle user registration
app.post("/register", async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("❌ Error registering user:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ✅ New GET "/title" endpoint
app.get("/title", (req, res) => {
  res.json({ message: "Title endpoint works!" });
});

// API endpoint to handle user login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: "Invalid username or password" });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: "Invalid username or password" });
  }
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful", token, role: user.role });
});

// Middleware to authenticate requests
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach the decoded user ID to the request
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token." });
  }
};

// API endpoint to fetch user dashboard
app.get("/dashboard", authenticate, async (req, res) => {
  try {
    // Fetch user details from the database
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Example response with user balances and account details
    res.status(200).json({
      username: user.username,
      email: user.email,
      balances: {
        savings: 5000,
        checking: 2000,
      },
    });
  } catch (error) {
    console.error("Error fetching dashboard data:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.delete('/manager/users/:id', authenticateAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(500).json({ message: 'Error deleting user' });
    }
});

app.get('/manager/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find({}, 'username email'); // Only return username and email
        res.json(users);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching users' });
    }
});

// Example admin authentication middleware
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token' });

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
}

// API endpoint to handle admin registration
app.post("/admin-register", async (req, res) => {
  const { username, email, password } = req.body;
  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existingUser) {
    return res.status(400).json({ message: "Username or email already exists" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword, role: "admin" });
  await user.save();
  res.status(201).json({ message: "Admin registered successfully" });
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});


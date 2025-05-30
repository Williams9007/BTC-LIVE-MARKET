const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const authenticateToken = require('./middleware/auth');
const morgan = require('morgan');

const app = express();
const PORT = 5000;
const SECRET_KEY = process.env.SECRET_KEY;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(morgan('dev'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    role: { type: String, default: 'user' }, // 'user' or 'manager'
});

const User = mongoose.model('User', userSchema);

// Routes

// Manager Login
app.post('/manager/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username, role: 'manager' });
    if (!user) return res.status(404).json({ message: 'Manager not found' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Get All Users (Manager Only)
app.get('/manager/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ message: 'Access denied. Manager only.' });
    }

    const users = await User.find({ role: 'user' });
    res.json(users);
});

// Add User (For Testing)
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.json({ message: 'User created successfully' });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
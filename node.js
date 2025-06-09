const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/auth_demo', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.log(err));

// User Model
const UserSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    phoneNumber: { type: String, required: true, unique: true },
    idNumber: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// JWT Secret
const JWT_SECRET = 'your_jwt_secret_key';

// Routes

// Register User
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, phoneNumber, idNumber } = req.body;

        // Validate input
        if (!fullName || !phoneNumber || !idNumber) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if phone number is in correct format (254xxxxxxxxx)
        if (!phoneNumber.startsWith('254') || phoneNumber.length !== 12 || !/^\d+$/.test(phoneNumber)) {
            return res.status(400).json({ message: 'Phone number must be in format 254xxxxxxxxx' });
        }

        // Check if ID number is valid (Kenyan ID format)
        if (idNumber.length !== 8 || !/^\d+$/.test(idNumber)) {
            return res.status(400).json({ message: 'ID number must be 8 digits' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ phoneNumber }, { idNumber }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this phone number or ID already exists' });
        }

        // Create new user
        const newUser = new User({
            fullName,
            phoneNumber,
            idNumber
        });

        await newUser.save();

        // Create token
        const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ 
            message: 'Registration successful', 
            token,
            user: {
                id: newUser._id,
                fullName: newUser.fullName,
                phoneNumber: newUser.phoneNumber
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login User
app.post('/api/login', async (req, res) => {
    try {
        const { phoneNumber, idNumber } = req.body;

        // Validate input
        if (!phoneNumber || !idNumber) {
            return res.status(400).json({ message: 'Phone number and ID number are required' });
        }

        // Find user
        const user = await User.findOne({ phoneNumber, idNumber });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Create token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ 
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                phoneNumber: user.phoneNumber
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

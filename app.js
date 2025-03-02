import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
// import crypto from 'crypto';


const app = express();
const PORT = 8081;

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/CryptoData', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
app.use(express.static('public'));

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

const cryptoHoldingSchema = new mongoose.Schema({
    name: { type: String, required: true },
    value: { type: String, required: true },
    baseNet: { type: String, required: true },
    From: { type: String, required: true },
    To: { type: String, required: true },
    amount: { type: Number, required: true },
    crypto: { type: String, required: true }
});

// User Schema for authentication (users collection)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    accountType: { type: String, default: 'Standard' },
    walletBalance: { type: Number, default: 0 },
    totalInvestment: { type: Number, default: 0 },
    lastUpdated: {
        type: Date,
        default: Date.now
    },
    cryptoHoldings: [cryptoHoldingSchema]
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// JWT Secret Key
const JWT_SECRET = 'your_jwt_secret_key';

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
}

// Signup API
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, email, password: hashedPassword });
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});


// Add Crypto Holdings:



// Get Crypto Summary endpoint


// Login route
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
        
        // Send user data along with token
        res.json({
            token,
            userData: {
                username: user.username,
                accountType: user.accountType,
                walletBalance: user.walletBalance,
                totalInvestment: user.totalInvestment,
                lastUpdated: user.lastUpdated,
                cryptoHoldings: user.cryptoHoldings
            }
        });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

app.post('/api/buy', async (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;

    try {
        const user = await User.findById(userId);
        const { name, value, baseNet, From, To, amount, crypto } = req.body;

        user.cryptoHoldings.push({ name, value, baseNet, From, To, amount, crypto });
        user.walletBalance -= parseFloat(value.replace('$', ''));
        user.totalInvestment += parseFloat(value.replace('$', ''));
        await user.save();
        res.json(user);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});
  
app.post('/api/sell', async (req, res) => {
    const { name, value, baseNet, From, To, amount, crypto } = req.body;
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;

    try {
        const user = await User.findById(userId);
        const holdingIndex = user.cryptoHoldings.findIndex((holding) => holding.name === name);
        if (holdingIndex === -1) {
            return res.status(400).json({ message: 'Crypto holding not found' });
        }
        user.cryptoHoldings.splice(holdingIndex, 1);
        user.walletBalance += parseFloat(value.replace('$', ''));
        user.totalInvestment -= parseFloat(value.replace('$', ''));
        await user.save();
        res.json(user);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});


        // Send user data along with token


// Password Reset Request Endpoint


// Change Password Endpoint



// Fetch User Data from UserData Collection
app.get('/api/UserData', async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId; // userId is the _id from the users collection

        const user = await User.findById(userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const userData = await User.findOne({ UserID: userId }).populate('UserID'); // Populate UserID if needed
        if (!userData) {
            return res.status(404).json({ message: 'User data not found' });
        }

        res.json(userData);
    } catch (error) {
        res.status(401).json({ message: 'Invalid token', error });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
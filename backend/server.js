// server.js
const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const productRoutes = require('./routes/productRoutes');
const authRoutes = require('./routes/authRoutes');
const cors = require('cors');

dotenv.config();
connectDB(); // Connect to MongoDB

const app = express();
app.use(express.json()); // Body parser

// CORS Configuration - Explicit whitelist
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5173',
    'https://inventory-mng-admin.vercel.app',
    'https://mechanic-bot-8ahf.onrender.com'
];

console.log('Allowed CORS Origins:', allowedOrigins);

// CORS middleware - Handle preflight requests
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    }
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

// --- Routes ---
app.get('/', (req, res) => {
    res.send('API is running...');
});

app.use('/api/auth', authRoutes);
app.use('/api/products', productRoutes);

// --- Server Listener ---
const PORT = process.env.PORT || 5000;

app.listen(
    PORT,
    console.log(`Server running on port ${PORT}`)
);
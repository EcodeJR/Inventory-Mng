// server.js
const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const productRoutes = require('./routes/productRoutes');
const authRoutes = require('./routes/authRoutes');
const cors = require('cors'); // Essential for connecting front-end

dotenv.config();
connectDB(); // Connect to MongoDB

const app = express();
app.use(express.json()); // Body parser

// CORS Configuration
const allowedOrigins = [
    'http://localhost:3000',
    'https://inventory-mng-admin.vercel.app',
    'https://mechanic-bot-8ahf.onrender.com',
    process.env.CORS_ORIGIN
].filter(Boolean); // Remove undefined values

app.use(cors({
    origin: function (origin, callback) {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

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
    console.log(`Server running in development mode on port ${PORT}`)
);
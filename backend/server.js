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
app.use(cors({ origin: 'http://localhost:5173' })); // Allow React front-end to connect

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
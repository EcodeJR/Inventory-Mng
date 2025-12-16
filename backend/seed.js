// backend/seed.js
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const Product = require('./models/ProductModel'); // Ensure this path is correct

dotenv.config();

const seedDatabase = async () => {
    try {
        // 1. Connect to MongoDB
        await mongoose.connect(process.env.MONGO_URI);
        console.log('📡 Connected to MongoDB for seeding...');

        // 2. Read the JSON file
        const filePath = path.join(__dirname, 'inventory.json');
        const fileData = fs.readFileSync(filePath, 'utf-8');
        const products = JSON.parse(fileData);

        // 3. Clear existing data (Optional: Remove if you want to keep old data)
        await Product.deleteMany({});
        console.log('🗑️  Existing products cleared.');

        // 4. Bulk Insert
        await Product.insertMany(products);
        console.log(`✅ Successfully imported ${products.length} products!`);

        // 5. Exit Process
        process.exit();
    } catch (error) {
        console.error('❌ Error seeding database:', error);
        process.exit(1);
    }
};

seedDatabase();
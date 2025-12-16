// routes/productRoutes.js
const express = require('express');
const Product = require('../models/ProductModel');
const { protect, admin } = require('../middleware/authMiddleware');
const router = express.Router();

// @desc    Admin: Create a new product
// @route   POST /api/products
// @access  Private (Admin-Only)
router.post('/', protect, admin, async (req, res) => {
    try {
        const product = new Product(req.body);
        const createdProduct = await product.save();
        res.status(201).json(createdProduct);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// @desc    Public: Get all products
// @route   GET /api/products
// @access  Public
router.get('/', async (req, res) => {
    const products = await Product.find({});
    res.json(products);
});

// @desc    Admin: Delete a product
// @route   DELETE /api/products/:id
// @access  Private (Admin-Only)
router.delete('/:id', protect, admin, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (product) {
            await product.deleteOne();
            res.json({ message: 'Product removed' });
        } else {
            res.status(404).json({ message: 'Product not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
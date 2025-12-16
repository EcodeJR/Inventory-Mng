// models/ProductModel.js
const mongoose = require('mongoose');

const productSchema = mongoose.Schema(
    {
        part_name: {
            type: String,
            required: true,
        },
        vehicle: {
            type: String,
            required: true,
        },
        year: {
            type: String,
            required: true,
        },
        price_NGN: {
            type: Number,
            required: true,
        },
        stock_qty: {
            type: Number,
            required: true,
            default: 0,
        },
        location: {
            type: String,
            required: true,
            default: "Warehouse A1",
        },
        image_url: {
            type: String,
            required: false, // Optional for simplicity in MVP
        }
    },
    {
        timestamps: true,
    }
);

const Product = mongoose.model('Product', productSchema);

module.exports = Product;
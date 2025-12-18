// frontend/src/components/ProductForm.js
import React, { useState, useContext } from 'react';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import './ProductForm.css';

const API_URL = 'https://inventory-mng-backend.vercel.app/products';

const ProductForm = () => {
    const { user } = useContext(AuthContext);
    const [formData, setFormData] = useState({
        part_name: '',
        vehicle: '',
        year: '',
        price_NGN: '',
        stock_qty: '',
        location: 'Warehouse A1',
        image_url: ''
    });
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setMessage('');

        try {
            const productData = {
                ...formData,
                year: parseInt(formData.year),
                price_NGN: parseFloat(formData.price_NGN),
                stock_qty: parseInt(formData.stock_qty)
            };

            const config = {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${user.token}`,
                },
            };

            const { data } = await axios.post(API_URL, productData, config);
            setMessage(`✅ Success! Product added with ID: ${data._id}`);
            setFormData({
                part_name: '', vehicle: '', year: '', price_NGN: '', 
                stock_qty: '', location: 'Warehouse A1', image_url: ''
            });
        } catch (error) {
            setMessage(`❌ Error: ${error.response?.data?.message || 'Server error'}`);
        } finally {
            setLoading(false);
        }
    };

    if (!user?.isAdmin) {
        return <div className="alert">⛔ Admin access required</div>;
    }

    return (
        <div className="product-form-container">
            <div className="form-card">
                <h2>⚙️ Add New Product</h2>
                <p className="form-subtitle">Add inventory to the database</p>

                <form onSubmit={handleSubmit}>
                    <input type="text" name="part_name" value={formData.part_name} onChange={handleChange} placeholder="Part Name" required />
                    <input type="text" name="vehicle" value={formData.vehicle} onChange={handleChange} placeholder="Vehicle Model" required />
                    <input type="number" name="year" value={formData.year} onChange={handleChange} placeholder="Year" required />
                    <input type="number" name="price_NGN" value={formData.price_NGN} onChange={handleChange} placeholder="Price (NGN)" required />
                    <input type="number" name="stock_qty" value={formData.stock_qty} onChange={handleChange} placeholder="Stock Quantity" required />
                    <input type="text" name="location" value={formData.location} onChange={handleChange} placeholder="Location" required />
                    <input type="text" name="image_url" value={formData.image_url} onChange={handleChange} placeholder="Image URL (Optional)" />
                    <button type="submit" disabled={loading}>
                        {loading ? 'Adding...' : 'Add Product'}
                    </button>
                </form>

                {message && <p className={`status-message ${message.includes('✅') ? 'success' : 'error'}`}>{message}</p>}
            </div>
        </div>
    );
};

export default ProductForm;
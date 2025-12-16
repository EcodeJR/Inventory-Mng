import React, { useState, useContext } from 'react';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import './LoginPage.css';

const API_URL = 'http://localhost:5000/api/auth';

const LoginPage = ({ onLoginSuccess }) => {
    const { login } = useContext(AuthContext);
    const [isLogin, setIsLogin] = useState(true);
    const [formData, setFormData] = useState({
        email: '',
        password: '',
        username: '',
        confirmPassword: '',
        adminSecret: '',
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
            const endpoint = isLogin ? '/login' : '/register';
            const { data } = await axios.post(API_URL + endpoint, formData);
            login(data);
            onLoginSuccess();
        } catch (error) {
            setMessage(error.response?.data?.message || 'An error occurred');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="login-container">
            <div className="login-card">
                <h1>⚙️ Mech-Bot Inventory</h1>
                <p className="subtitle">{isLogin ? 'Sign In' : 'Create Account'}</p>

                <form onSubmit={handleSubmit}>
                    {!isLogin && (
                        <input
                            type="text"
                            name="username"
                            placeholder="Username"
                            value={formData.username}
                            onChange={handleChange}
                            required={!isLogin}
                        />
                    )}
                    <input
                        type="email"
                        name="email"
                        placeholder="Email"
                        value={formData.email}
                        onChange={handleChange}
                        required
                    />
                    <input
                        type="password"
                        name="password"
                        placeholder="Password"
                        value={formData.password}
                        onChange={handleChange}
                        required
                    />
                    {!isLogin && (
                        <>
                            <input
                                type="password"
                                name="confirmPassword"
                                placeholder="Confirm Password"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                required={!isLogin}
                            />
                            <input
                                type="password"
                                name="adminSecret"
                                placeholder="Admin Secret (Optional)"
                                value={formData.adminSecret}
                                onChange={handleChange}
                            />
                        </>
                    )}
                    <button type="submit" disabled={loading}>
                        {loading ? 'Loading...' : isLogin ? 'Sign In' : 'Create Account'}
                    </button>
                </form>

                {message && <p className="error-message">{message}</p>}

                <p className="toggle-text">
                    {isLogin ? "Don't have an account?" : 'Already have an account?'}
                    <button type="button" onClick={() => setIsLogin(!isLogin)}>
                        {isLogin ? ' Sign Up' : ' Sign In'}
                    </button>
                </p>
            </div>
        </div>
    );
};

export default LoginPage;

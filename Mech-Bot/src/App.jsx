// frontend/src/App.js
import React, { useContext } from 'react';
import { AuthContext } from './context/AuthContext';
import LoginPage from './components/LoginPage';
import Navbar from './components/Navbar';
import ProductForm from './components/ProductForm';
import './App.css';

function App() {
    const { user, logout, loading } = useContext(AuthContext);

    if (loading) {
        return <div className="loading">Loading...</div>;
    }

    if (!user) {
        return <LoginPage onLoginSuccess={() => {}} />;
    }

    return (
        <div className="App">
            <Navbar onLogout={logout} />
            <ProductForm />
        </div>
    );
}

export default App;
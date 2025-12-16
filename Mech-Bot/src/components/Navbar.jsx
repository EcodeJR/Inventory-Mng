import React, { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import './Navbar.css';

const Navbar = ({ onLogout }) => {
    const { user } = useContext(AuthContext);

    return (
        <nav className="navbar">
            <div className="navbar-container">
                <div className="navbar-brand">⚙️ Mech-Bot</div>
                <div className="navbar-user">
                    <span className="user-info">
                        {user?.username} {user?.isAdmin && <span className="admin-badge">ADMIN</span>}
                    </span>
                    <button onClick={onLogout} className="logout-btn">
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

app.use(express.json()); // For parsing JSON request bodies

// --- PostgreSQL Database Configuration ---
const pool = new Pool({
    user: 'your_db_user',
    host: 'localhost',
    database: 'anime_community',
    password: 'your_db_password',
    port: 5432,
});

// Test DB connection
pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to PostgreSQL database');
        done();
    }
});

// --- User Registration Endpoint ---
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username!email!password) {
    return res.status(400).json({ message: 'All fields are required.' });
}

try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
        'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username',
        [username, email, hashedPassword]
    );
    res.status(201).json({ message: 'User registered successfully!', user: result.rows[0] });
} catch (error) {
    if (error.code === '23505') { // Unique violation error code
        return res.status(409).json({ message: 'Username or email already exists.' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration.' });
}
                                                                                                                                                                                            });

// --- User Login Endpoint ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT Token (replace 'your_jwt_secret' with a strong, secret key)
        const token = jwt.sign({ userId: user.id, username: user.username }, 'your_jwt_secret', { expiresIn: '1h' });
        res.json({ message: 'Logged in successfully!', token });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- Example Protected Route (requires authentication) ---
// This is a middleware function to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No token

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token
        req.user = user;
        next();
    });
};

app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email FROM users WHERE id = $1', [req.user.userId]);
        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Server error fetching profile.' });
    }
});


// --- Start Server ---
app.listen(port, () => {
    console.log(Server listening at http://localhost:${port});
                                                                                                                                                                                                                                                                                                                                                                                                                                });


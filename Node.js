// Simple Node.js + Express backend for login and register const express = require('express'); const cors = require('cors'); const bcrypt = require('bcryptjs'); const jwt = require('jsonwebtoken'); const path = require('path');

const app = express(); const PORT = process.env.PORT || 5000; const SECRET_KEY = 'laam_secret_key';

app.use(cors()); app.use(express.json()); app.use(express.static(path.join(__dirname, 'public'))); // Serve frontend

const users = [];

app.post('/api/register', async (req, res) => { const { username, password } = req.body; if (!username || !password) return res.status(400).json({ message: 'All fields required.' });

const existing = users.find(u => u.username === username); if (existing) return res.status(400).json({ message: 'User already exists.' });

const hashed = await bcrypt.hash(password, 10); users.push({ username, password: hashed }); res.status(201).json({ message: 'User registered successfully.' }); });

app.post('/api/login', async (req, res) => { const { username, password } = req.body; const user = users.find(u => u.username === username); if (!user) return res.status(400).json({ message: 'Invalid username or password.' });

const valid = await bcrypt.compare(password, user.password); if (!valid) return res.status(400).json({ message: 'Invalid username or password.' });

const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '2h' }); res.json({ message: 'Login successful', token }); });

app.get('/api/profile', (req, res) => { const auth = req.headers.authorization; if (!auth) return res.status(401).json({ message: 'No token provided' });

try { const decoded = jwt.verify(auth.split(' ')[1], SECRET_KEY); res.json({ message: 'Profile data', user: decoded }); } catch (err) { res.status(401).json({ message: 'Invalid token' }); } });

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public/index.html')); });

app.listen(PORT, () => console.log(Server running on http://localhost:${PORT}));


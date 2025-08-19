// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const db = require('./db');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware to handle both JSON and form data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// =================== REGISTER ===================
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send('All fields are required.');
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';

  db.query(sql, [username, email, hashedPassword], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Registration failed.');
    }
    res.status(200).send('Registered successfully.');
  });
});

// =================== LOGIN ===================
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required.');
  }

  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], (err, results) => {
    if (err) return res.status(500).send('Database error.');
    if (results.length === 0) return res.status(401).send('User not found.');

    const user = results[0];
    const match = bcrypt.compareSync(password, user.password);

    if (match) {
      return res.status(200).send('Login successful.');
    } else {
      return res.status(401).send('Invalid credentials.');
    }
  });
});

// =================== START SERVER ===================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

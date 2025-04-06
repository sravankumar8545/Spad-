
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const db = new sqlite3.Database('./database.db');

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Create user table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeId TEXT,
    mobileNumber TEXT UNIQUE,
    dateOfJoining TEXT,
    pfNumber TEXT,
    password TEXT
)`);

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { employeeId, mobileNumber, dateOfJoining, pfNumber, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const stmt = db.prepare('INSERT INTO users (employeeId, mobileNumber, dateOfJoining, pfNumber, password) VALUES (?, ?, ?, ?, ?)');
    stmt.run(employeeId, mobileNumber, dateOfJoining, pfNumber, hashedPassword, function (err) {
        if (err) return res.status(400).json({ message: 'Mobile number already registered.' });
        res.json({ message: 'Signup successful!' });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { mobileNumber, password } = req.body;

    db.get('SELECT * FROM users WHERE mobileNumber = ?', [mobileNumber], async (err, user) => {
        if (err || !user) return res.status(400).json({ message: 'Invalid mobile number or password.' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ message: 'Invalid mobile number or password.' });

        res.json({
            message: 'Login successful',
            user: {
                employeeId: user.employeeId,
                mobileNumber: user.mobileNumber,
                dateOfJoining: user.dateOfJoining,
                pfNumber: user.pfNumber
            }
        });
    });
});

app.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});

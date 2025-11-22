const db = require('../db/db');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

// Register user
const registerUser = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "All fields are required" });

    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPassword],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ message: "User registered successfully" });
        }
    );
};

// Login user
const loginUser = (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields required" });

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ message: "User not found" });

        const match = await bcrypt.compare(password, results[0].password);
        if (!match) return res.status(401).json({ message: "Invalid password" });

        res.json({ message: "Login successful" });
    });
};

// Forgot password (send OTP via Gmail)
const forgotPassword = (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const otp = Math.floor(100000 + Math.random() * 900000);

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.GMAIL_USER,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP for password reset is ${otp}`
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "OTP sent to email", otp }); // Remove otp in production
    });
};

module.exports = { registerUser, loginUser, forgotPassword };

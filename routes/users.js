const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Otp = require('../models/OTP');
const sendOtpEmail = require('../utils/sendOtpEmail');

// Middleware to verify JWT token
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// POST register route
router.post('/register', async (req, res) => {
  const { firstName, lastName, role, username, email, password } = req.body;

  try {
    if (!/^[^\s@]+@student\.kpu\.ca$/i.test(email)) {
      return res.status(400).json({
        message: 'Only KPU emails are allowed.',
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ message: 'User already exists. Please login.' });
    }

    const user = new User({
      firstName,
      lastName,
      role,
      username,
      email,
      password,
      isVerified: false,
      isApproved: false, // Fixed typo: isApproed -> isApproved
    });

    await user.save();
    console.log('✅ User saved to DB:', user.email);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiryTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await Otp.findOneAndUpdate(
      { email },
      { otp, createdAt: new Date(), expiresAt: expiryTime },
      { upsert: true }
    );

    console.log('🛂 OTP generated:', otp);

    await sendOtpEmail(email, otp);

    res.status(200).json({ message: 'User registered. OTP sent to email.' });
  } catch (err) {
    console.error('REGISTER ERROR:', err);
    res.status(500).json({
      message: 'Failed to register user',
      error: err.message || err.toString(),
    });
  }
});

// Login route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user)
      return res.status(404).json({
        message: 'User not found',
      });

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return res.status(400).json({
        message: 'Invalid credentials',
      });

    if (!user.isVerified) {
      return res.status(401).json({
        message: 'User not verified. Please verify your email first.',
      });
    }

    if (user.role === 'mentor' && user.isApproved === false) {
      return res.status(403).json({
        message: 'Your account is awaiting admin approval.',
      });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '2h',
    });

    res.status(200).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
      message: 'Login successful',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Login failed' });
  }
});

// GET user role and name
router.get('/user-info', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('firstName lastName role');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      message: 'User info retrieved successfully'
    });
  } catch (err) {
    console.error('USER INFO ERROR:', err);
    res.status(500).json({
      message: 'Failed to retrieve user info',
      error: err.message || err.toString()
    });
  }
});

module.exports = router;

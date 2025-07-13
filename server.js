const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 0 },
  totalEarned: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  lastActivity: { type: Date, default: Date.now },
  onlineTime: { type: Number, default: 0 }, // in seconds
  videosWatched: { type: Number, default: 0 },
  referralCode: String,
  referredBy: String,
  createdAt: { type: Date, default: Date.now }
});

// Video Schema
const videoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  filename: { type: String, required: true },
  originalName: String,
  mimetype: String,
  size: Number,
  duration: Number, // in seconds
  views: { type: Number, default: 0 },
  earnings: { type: Number, default: 0 }, // earnings per view
  isActive: { type: Boolean, default: true },
  uploadedAt: { type: Date, default: Date.now }
});

// Video Watch History Schema
const watchHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  videoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Video', required: true },
  watchedDuration: { type: Number, required: true }, // in seconds
  earnedAmount: { type: Number, default: 0 },
  watchedAt: { type: Date, default: Date.now }
});

// Payment Request Schema
const paymentRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  method: { type: String, enum: ['mpesa', 'paypal'], required: true },
  accountDetails: { type: String, required: true }, // phone number or email
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  transactionId: String,
  createdAt: { type: Date, default: Date.now },
  processedAt: Date
});

// App Settings Schema
const appSettingsSchema = new mongoose.Schema({
  appName: { type: String, default: 'WatchEarn' },
  videoEarningsPer30Sec: { type: Number, default: 0.01 },
  onlineEarningsPer60Sec: { type: Number, default: 0.005 },
  minimumPayout: { type: Number, default: 1.0 },
  ownerEarningsPerSecond: { type: Number, default: 0.001 },
  referralBonus: { type: Number, default: 0.5 },
  isMaintenanceMode: { type: Boolean, default: false },
  lastUpdated: { type: Date, default: Date.now }
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'super_admin'], default: 'admin' },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

// Owner Earnings Schema
const ownerEarningsSchema = new mongoose.Schema({
  totalEarnings: { type: Number, default: 0 },
  todayEarnings: { type: Number, default: 0 },
  lastReset: { type: Date, default: Date.now },
  earningsHistory: [{
    date: { type: Date, default: Date.now },
    amount: Number,
    source: String // 'user_activity', 'video_watch', etc.
  }]
});

// Models
const User = mongoose.model('User', userSchema);
const Video = mongoose.model('Video', videoSchema);
const WatchHistory = mongoose.model('WatchHistory', watchHistorySchema);
const PaymentRequest = mongoose.model('PaymentRequest', paymentRequestSchema);
const AppSettings = mongoose.model('AppSettings', appSettingsSchema);
const Admin = mongoose.model('Admin', adminSchema);
const OwnerEarnings = mongoose.model('OwnerEarnings', ownerEarningsSchema);

// Email configuration
const transporter = nodemailer.createTransporter({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/videos/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /mp4|avi|mov|wmv|flv|webm/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only video files are allowed'));
    }
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Admin authentication middleware
const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Admin access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);
    if (!admin) {
      return res.status(401).json({ error: 'Admin not found' });
    }
    req.admin = admin;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid admin token' });
  }
};

// Generate referral code
const generateReferralCode = () => {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
};

// USER ROUTES

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, referralCode } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate verification token
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      verificationToken,
      referralCode: generateReferralCode(),
      referredBy: referralCode
    });

    await user.save();

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Verify Your Email',
      html: `
        <h2>Welcome to WatchEarn!</h2>
        <p>Please click the link below to verify your email address:</p>
        <a href="${verificationUrl}">Verify Email</a>
        <p>This link expires in 24 hours.</p>
      `
    });

    res.status(201).json({ 
      message: 'User registered successfully. Please check your email for verification.',
      referralCode: user.referralCode
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Email Verification
app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const { token } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ email: decoded.email, verificationToken: token });

    if (!user) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    
    // Add referral bonus if user was referred
    if (user.referredBy) {
      const referrer = await User.findOne({ referralCode: user.referredBy });
      if (referrer) {
        const settings = await AppSettings.findOne() || new AppSettings();
        referrer.balance += settings.referralBonus;
        referrer.totalEarned += settings.referralBonus;
        await referrer.save();
      }
    }

    await user.save();

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired verification token' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ error: 'Please verify your email first' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    // Update last activity
    user.lastActivity = new Date();
    await user.save();

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        balance: user.balance,
        totalEarned: user.totalEarned,
        referralCode: user.referralCode
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Online Time and Earnings
app.post('/api/user/update-activity', authenticateToken, async (req, res) => {
  try {
    const { timeSpent } = req.body; // time spent in seconds
    const settings = await AppSettings.findOne() || new AppSettings();
    
    // Calculate user earnings for being online (every 60 seconds)
    const onlineEarnings = Math.floor(timeSpent / 60) * settings.onlineEarningsPer60Sec;
    
    // Calculate owner earnings (every second)
    const ownerEarnings = timeSpent * settings.ownerEarningsPerSecond;
    
    // Update user
    const user = await User.findById(req.user._id);
    user.onlineTime += timeSpent;
    user.balance += onlineEarnings;
    user.totalEarned += onlineEarnings;
    user.lastActivity = new Date();
    await user.save();
    
    // Update owner earnings
    let ownerEarningsDoc = await OwnerEarnings.findOne();
    if (!ownerEarningsDoc) {
      ownerEarningsDoc = new OwnerEarnings();
    }
    
    ownerEarningsDoc.totalEarnings += ownerEarnings;
    ownerEarningsDoc.todayEarnings += ownerEarnings;
    ownerEarningsDoc.earningsHistory.push({
      amount: ownerEarnings,
      source: 'user_activity'
    });
    await ownerEarningsDoc.save();
    
    res.json({
      message: 'Activity updated successfully',
      earned: onlineEarnings,
      newBalance: user.balance
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Videos
app.get('/api/videos', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const videos = await Video.find({ isActive: true })
      .sort({ uploadedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select('-filename'); // Don't expose file paths

    const total = await Video.countDocuments({ isActive: true });
    
    res.json({
      videos,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Watch Video
app.post('/api/videos/:id/watch', authenticateToken, async (req, res) => {
  try {
    const { watchedDuration } = req.body; // in seconds
    const videoId = req.params.id;
    
    const video = await Video.findById(videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const settings = await AppSettings.findOne() || new AppSettings();
    
    // Calculate earnings (user gets paid for every 30 seconds watched)
    const earningsSegments = Math.floor(watchedDuration / 30);
    const earnings = earningsSegments * settings.videoEarningsPer30Sec;
    
    // Update user earnings
    const user = await User.findById(req.user._id);
    user.balance += earnings;
    user.totalEarned += earnings;
    user.videosWatched += 1;
    user.lastActivity = new Date();
    await user.save();
    
    // Update video stats
    video.views += 1;
    video.earnings += earnings;
    await video.save();
    
    // Record watch history
    const watchHistory = new WatchHistory({
      userId: req.user._id,
      videoId: videoId,
      watchedDuration: watchedDuration,
      earnedAmount: earnings
    });
    await watchHistory.save();
    
    // Update owner earnings
    let ownerEarningsDoc = await OwnerEarnings.findOne();
    if (!ownerEarningsDoc) {
      ownerEarningsDoc = new OwnerEarnings();
    }
    
    const ownerEarnings = watchedDuration * settings.ownerEarningsPerSecond;
    ownerEarningsDoc.totalEarnings += ownerEarnings;
    ownerEarningsDoc.todayEarnings += ownerEarnings;
    ownerEarningsDoc.earningsHistory.push({
      amount: ownerEarnings,
      source: 'video_watch'
    });
    await ownerEarningsDoc.save();
    
    res.json({
      message: 'Video watch recorded successfully',
      earned: earnings,
      newBalance: user.balance
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Request Payment
app.post('/api/payments/request', authenticateToken, async (req, res) => {
  try {
    const { amount, method, accountDetails } = req.body;
    const settings = await AppSettings.findOne() || new AppSettings();
    
    if (amount < settings.minimumPayout) {
      return res.status(400).json({ error: `Minimum payout is ${settings.minimumPayout}` });
    }
    
    const user = await User.findById(req.user._id);
    if (user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const paymentRequest = new PaymentRequest({
      userId: req.user._id,
      amount,
      method,
      accountDetails
    });
    
    await paymentRequest.save();
    
    res.json({ message: 'Payment request submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Payment History
app.get('/api/payments/history', authenticateToken, async (req, res) => {
  try {
    const payments = await PaymentRequest.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    
    res.json(payments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ADMIN ROUTES

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    
    admin.lastLogin = new Date();
    await admin.save();
    
    res.json({
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Dashboard Stats
app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalVideos = await Video.countDocuments();
    const totalEarnings = await OwnerEarnings.findOne() || { totalEarnings: 0, todayEarnings: 0 };
    const pendingPayments = await PaymentRequest.countDocuments({ status: 'pending' });
    
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('-password');
    
    const recentVideos = await Video.find()
      .sort({ uploadedAt: -1 })
      .limit(5);
    
    res.json({
      totalUsers,
      totalVideos,
      totalEarnings: totalEarnings.totalEarnings,
      todayEarnings: totalEarnings.todayEarnings,
      pendingPayments,
      recentUsers,
      recentVideos
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get All Users
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    
    const filter = search 
      ? { email: { $regex: search, $options: 'i' } }
      : {};
    
    const users = await User.find(filter)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await User.countDocuments(filter);
    
    res.json({
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update User Balance
app.patch('/api/admin/users/:id/balance', authenticateAdmin, async (req, res) => {
  try {
    const { balance } = req.body;
    const userId = req.params.id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.balance = balance;
    await user.save();
    
    res.json({ message: 'User balance updated successfully', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Upload Video
app.post('/api/admin/videos/upload', authenticateAdmin, upload.single('video'), async (req, res) => {
  try {
    const { title, description, duration } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'Video file is required' });
    }
    
    const video = new Video({
      title,
      description,
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      duration: parseInt(duration) || 0
    });
    
    await video.save();
    
    res.json({ message: 'Video uploaded successfully', video });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get All Videos (Admin)
app.get('/api/admin/videos', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    
    const videos = await Video.find()
      .sort({ uploadedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await Video.countDocuments();
    
    res.json({
      videos,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Video
app.delete('/api/admin/videos/:id', authenticateAdmin, async (req, res) => {
  try {
    const video = await Video.findByIdAndDelete(req.params.id);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    res.json({ message: 'Video deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Payment Requests
app.get('/api/admin/payments', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = 'all' } = req.query;
    
    const filter = status !== 'all' ? { status } : {};
    
    const payments = await PaymentRequest.find(filter)
      .populate('userId', 'email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await PaymentRequest.countDocuments(filter);
    
    res.json({
      payments,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve/Reject Payment
app.patch('/api/admin/payments/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, transactionId } = req.body;
    const paymentId = req.params.id;
    
    const payment = await PaymentRequest.findById(paymentId).populate('userId');
    if (!payment) {
      return res.status(404).json({ error: 'Payment request not found' });
    }
    
    if (status === 'approved') {
      // Process payment based on method
      if (payment.method === 'mpesa') {
        // Implement M-Pesa payment logic here
        await processMpesaPayment(payment);
      } else if (payment.method === 'paypal') {
        // Implement PayPal payment logic here
        await processPayPalPayment(payment);
      }
      
      // Deduct from user balance
      const user = payment.userId;
      user.balance -= payment.amount;
      await user.save();
    }
    
    payment.status = status;
    payment.transactionId = transactionId;
    payment.processedAt = new Date();
    await payment.save();
    
    res.json({ message: `Payment ${status} successfully`, payment });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get App Settings
app.get('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    let settings = await AppSettings.findOne();
    if (!settings) {
      settings = new AppSettings();
      await settings.save();
    }
    
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update App Settings
app.put('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const updates = req.body;
    
    let settings = await AppSettings.findOne();
    if (!settings) {
      settings = new AppSettings();
    }
    
    Object.assign(settings, updates);
    settings.lastUpdated = new Date();
    await settings.save();
    
    res.json({ message: 'Settings updated successfully', settings });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reset App Data
app.post('/api/admin/reset-app', authenticateAdmin, async (req, res) => {
  try {
    const { resetType } = req.body;
    
    if (resetType === 'users') {
      await User.deleteMany({});
    } else if (resetType === 'videos') {
      await Video.deleteMany({});
      await WatchHistory.deleteMany({});
    } else if (resetType === 'payments') {
      await PaymentRequest.deleteMany({});
    } else if (resetType === 'all') {
      await User.deleteMany({});
      await Video.deleteMany({});
      await WatchHistory.deleteMany({});
      await PaymentRequest.deleteMany({});
      await OwnerEarnings.deleteMany({});
    }
    
    res.json({ message: `${resetType} data reset successfully` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Payment Processing Functions
async function processMpesaPayment(payment) {
  try {
    // M-Pesa STK Push implementation
    const response = await axios.post(
      `${process.env.MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
      {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: process.env.MPESA_PASSWORD,
        Timestamp: new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3),
        TransactionType: 'CustomerPayBillOnline',
        Amount: payment.amount,
        PartyA: payment.accountDetails,
        PartyB: process.env.MPESA_SHORTCODE,
        PhoneNumber: payment.accountDetails,
        CallBackURL: `${process.env.BASE_URL}/api/payments/mpesa/callback`,
        AccountReference: `PAY-${payment._id}`,
        TransactionDesc: 'WatchEarn Payment'
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.MPESA_ACCESS_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    return response.data;
  } catch (error) {
    throw new Error(`M-Pesa payment failed: ${error.message}`);
  }
}

async function processPayPalPayment(payment) {
  try {
    // PayPal payout implementation
    const response = await axios.post(
      `${process.env.PAYPAL_BASE_URL}/v1/payments/payouts`,
      {
        sender_batch_header: {
          sender_batch_id: `batch-${payment._id}`,
          email_subject: 'You have a payout!',
          email_message: 'You have received a payout from WatchEarn!'
        },
        items: [{
          recipient_type: 'EMAIL',
          amount: {
            value: payment.amount.toString(),
            currency: 'USD'
          },
          receiver: payment.accountDetails,
          note: 'Payment from WatchEarn',
          sender_item_id: `item-${payment._id}`
        }]
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.PAYPAL_ACCESS_TOKEN}`
        }
      }
    );
    
    return response.data;
  } catch (error) {
    throw new Error(`PayPal payment failed: ${error.message}`);
  }
}

// M-Pesa Callback
app.post('/api/payments/mpesa/callback', async (req, res) => {
  try {
    const { Body } = req.body;
    
    if (Body.stkCallback.ResultCode === 0) {
      // Payment successful
      const accountReference = Body.stkCallback.CallbackMetadata.Item.find(
        item => item.Name === 'AccountReference'
      ).Value;
      
      const paymentId = accountReference.replace('PAY-', '');
      const payment = await PaymentRequest.findById(paymentId);
      
      if (payment) {
        payment.status = 'approved';
        payment.transactionId = Body.stkCallback.CheckoutRequestID;
        payment.processedAt = new Date();
        await payment.save();
        
        // Deduct from user balance
        const user = await User.findById(payment.userId);
        user.balance -= payment.amount;
        await user.save();
      }
    }
    
    res.status(200).json({ message: 'Callback received' });
  } catch (error) {
    console.error('M-Pesa callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

// Create Default Admin (Run once)
app.post('/api/admin/create-default', async (req, res) => {
  try {
    const existingAdmin = await Admin.findOne({ username: 'admin' });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Default admin already exists' });
    }
    
    const hashedPassword = await bcrypt.hash('admin123', 10);
    
    const admin = new Admin({
      username: 'admin',
      email: 'admin@watchearn.com',
      password: hashedPassword,
      role: 'super_admin'
    });
    
    await admin.save();
    
    res.json({ message: 'Default admin created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Owner Earnings
app.get('/api/admin/owner-earnings', authenticateAdmin, async (req, res) => {
  try {
    let earnings = await OwnerEarnings.findOne();
    if (!earnings) {
      earnings = new OwnerEarnings();
      await earnings.save();
    }
    
    res.json(earnings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reset Daily Earnings
app.post('/api/admin/reset-daily-earnings', authenticateAdmin, async (req, res) => {
  try {
    let earnings = await OwnerEarnings.findOne();
    if (!earnings) {
      earnings = new OwnerEarnings();
    }
    
    earnings.todayEarnings = 0;
    earnings.lastReset = new Date();
    await earnings.save();
    
    res.json({ message: 'Daily earnings reset successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Analytics
app.get('/api/admin/analytics', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    
    let dateFilter = {};
    const now = new Date();
    
    switch (period) {
      case '24h':
        dateFilter = { createdAt: { $gte: new Date(now - 24 * 60 * 60 * 1000) } };
        break;
      case '7d':
        dateFilter = { createdAt: { $gte: new Date(now - 7 * 24 * 60 * 60 * 1000) } };
        break;
      case '30d':
        dateFilter = { createdAt: { $gte: new Date(now - 30 * 24 * 60 * 60 * 1000) } };
        break;
      case '90d':
        dateFilter = { createdAt: { $gte: new Date(now - 90 * 24 * 60 * 60 * 1000) } };
        break;
    }
    
    const [
      newUsers,
      totalVideoViews,
      totalPayments,
      activeUsers
    ] = await Promise.all([
      User.countDocuments(dateFilter),
      WatchHistory.countDocuments(dateFilter),
      PaymentRequest.countDocuments(dateFilter),
      User.countDocuments({
        lastActivity: { $gte: new Date(now - 24 * 60 * 60 * 1000) }
      })
    ]);
    
    // Get earnings by day
    const earningsHistory = await OwnerEarnings.findOne();
    const dailyEarnings = earningsHistory ? earningsHistory.earningsHistory.filter(
      e => e.date >= new Date(now - 30 * 24 * 60 * 60 * 1000)
    ) : [];
    
    res.json({
      newUsers,
      totalVideoViews,
      totalPayments,
      activeUsers,
      dailyEarnings
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Bulk Operations
app.post('/api/admin/bulk-operations', authenticateAdmin, async (req, res) => {
  try {
    const { operation, userIds, amount } = req.body;
    
    switch (operation) {
      case 'addBalance':
        await User.updateMany(
          { _id: { $in: userIds } },
          { $inc: { balance: amount, totalEarned: amount } }
        );
        break;
      case 'deductBalance':
        await User.updateMany(
          { _id: { $in: userIds } },
          { $inc: { balance: -amount } }
        );
        break;
      case 'resetBalance':
        await User.updateMany(
          { _id: { $in: userIds } },
          { $set: { balance: 0 } }
        );
        break;
      case 'deleteUsers':
        await User.deleteMany({ _id: { $in: userIds } });
        break;
    }
    
    res.json({ message: `Bulk ${operation} completed successfully` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Export Data
app.get('/api/admin/export/:type', authenticateAdmin, async (req, res) => {
  try {
    const { type } = req.params;
    let data;
    
    switch (type) {
      case 'users':
        data = await User.find().select('-password');
        break;
      case 'videos':
        data = await Video.find();
        break;
      case 'payments':
        data = await PaymentRequest.find().populate('userId', 'email');
        break;
      case 'watch-history':
        data = await WatchHistory.find()
          .populate('userId', 'email')
          .populate('videoId', 'title');
        break;
      default:
        return res.status(400).json({ error: 'Invalid export type' });
    }
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=${type}-export.json`);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Video Streaming Endpoint
app.get('/api/videos/:id/stream', authenticateToken, async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const videoPath = path.join(__dirname, 'uploads', 'videos', video.filename);
    const stat = require('fs').statSync(videoPath);
    const fileSize = stat.size;
    const range = req.headers.range;
    
    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunksize = (end - start) + 1;
      const file = require('fs').createReadStream(videoPath, { start, end });
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': 'video/mp4',
      };
      res.writeHead(206, head);
      file.pipe(res);
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': 'video/mp4',
      };
      res.writeHead(200, head);
      require('fs').createReadStream(videoPath).pipe(res);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Scheduled Tasks (Run with cron jobs)
const resetDailyEarnings = async () => {
  try {
    await OwnerEarnings.updateOne(
      {},
      { $set: { todayEarnings: 0, lastReset: new Date() } }
    );
    console.log('Daily earnings reset completed');
  } catch (error) {
    console.error('Error resetting daily earnings:', error);
  }
};

// Clean up old verification tokens
const cleanupExpiredTokens = async () => {
  try {
    await User.deleteMany({
      isVerified: false,
      createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });
    console.log('Expired tokens cleanup completed');
  } catch (error) {
    console.error('Error cleaning up expired tokens:', error);
  }
};

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  // Run cleanup tasks every hour
  setInterval(cleanupExpiredTokens, 60 * 60 * 1000);
  
  // Reset daily earnings at midnight
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setDate(now.getDate() + 1);
  tomorrow.setHours(0, 0, 0, 0);
  
  const msUntilMidnight = tomorrow.getTime() - now.getTime();
  setTimeout(() => {
    resetDailyEarnings();
    setInterval(resetDailyEarnings, 24 * 60 * 60 * 1000);
  }, msUntilMidnight);
});

module.exports = app;

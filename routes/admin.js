const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const axios = require('axios');

const router = express.Router();

// Import models (assuming they're exported from your main server file or models file)
// You'll need to adjust these imports based on your actual file structure
const User = require('../models/User'); // Adjust path as needed
const Video = require('../models/Video');
const WatchHistory = require('../models/WatchHistory');
const PaymentRequest = require('../models/PaymentRequest');
const AppSettings = require('../models/AppSettings');
const Admin = require('../models/Admin');
const OwnerEarnings = require('../models/OwnerEarnings');
const OwnerWithdrawal = require('../models/OwnerWithdrawal');

// File upload configuration for admin video uploads
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

// AUTHENTICATION ROUTES

// Admin Login
router.post('/login', async (req, res) => {
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

// Create Default Admin (Run once)
router.post('/create-default', async (req, res) => {
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

// DASHBOARD ROUTES

// Get Dashboard Statistics
router.get('/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalVideos = await Video.countDocuments();
    const totalEarnings = await OwnerEarnings.findOne() || { totalEarnings: 0, todayEarnings: 0 };
    const pendingPayments = await PaymentRequest.countDocuments({ status: 'pending' });
    const pendingWithdrawals = await OwnerWithdrawal.countDocuments({ status: 'pending' });
    
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('-password');
    
    const recentVideos = await Video.find()
      .sort({ uploadedAt: -1 })
      .limit(5);
    
    const recentWithdrawals = await OwnerWithdrawal.find()
      .sort({ createdAt: -1 })
      .limit(5);
    
    res.json({
      totalUsers,
      totalVideos,
      totalEarnings: totalEarnings.totalEarnings,
      todayEarnings: totalEarnings.todayEarnings,
      pendingPayments,
      pendingWithdrawals,
      recentUsers,
      recentVideos,
      recentWithdrawals
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Analytics
router.get('/analytics', authenticateAdmin, async (req, res) => {
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

// USER MANAGEMENT ROUTES

// Get All Users
router.get('/users', authenticateAdmin, async (req, res) => {
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
router.patch('/users/:id/balance', authenticateAdmin, async (req, res) => {
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

// Bulk Operations
router.post('/bulk-operations', authenticateAdmin, async (req, res) => {
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

// VIDEO MANAGEMENT ROUTES

// Upload Video
router.post('/videos/upload', authenticateAdmin, upload.single('video'), async (req, res) => {
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
router.get('/videos', authenticateAdmin, async (req, res) => {
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

// Update Video
router.patch('/videos/:id', authenticateAdmin, async (req, res) => {
  try {
    const { title, description, isActive } = req.body;
    const videoId = req.params.id;
    
    const video = await Video.findById(videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    if (title) video.title = title;
    if (description) video.description = description;
    if (typeof isActive !== 'undefined') video.isActive = isActive;
    
    await video.save();
    
    res.json({ message: 'Video updated successfully', video });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Video
router.delete('/videos/:id', authenticateAdmin, async (req, res) => {
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

// PAYMENT MANAGEMENT ROUTES

// Get Payment Requests
router.get('/payments', authenticateAdmin, async (req, res) => {
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
router.patch('/payments/:id', authenticateAdmin, async (req, res) => {
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
        await processMpesaPayment(payment);
      } else if (payment.method === 'paypal') {
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

// OWNER EARNINGS & WITHDRAWAL ROUTES

// Get Owner Earnings
router.get('/owner-earnings', authenticateAdmin, async (req, res) => {
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
router.post('/reset-daily-earnings', authenticateAdmin, async (req, res) => {
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

// Request Owner Withdrawal
router.post('/owner/withdraw', authenticateAdmin, async (req, res) => {
  try {
    const { amount, method, notes } = req.body;
    
    // Check withdrawal limits
    const limits = {
      mpesa: parseFloat(process.env.MPESA_WITHDRAW_LIMIT) || 70000,
      bank: parseFloat(process.env.BANK_WITHDRAW_LIMIT) || 1000000,
      paypal: parseFloat(process.env.PAYPAL_WITHDRAW_LIMIT) || 10000
    };
    
    if (amount > limits[method]) {
      return res.status(400).json({ 
        error: `Amount exceeds ${method.toUpperCase()} limit of ${limits[method]}` 
      });
    }
    
    // Check available balance
    const ownerEarnings = await OwnerEarnings.findOne();
    if (!ownerEarnings || ownerEarnings.totalEarnings < amount) {
      return res.status(400).json({ error: 'Insufficient owner earnings' });
    }
    
    // Get account details from environment
    let accountDetails;
    switch (method) {
      case 'mpesa':
        accountDetails = process.env.OWNER_MPESA_NUMBER;
        break;
      case 'bank':
        accountDetails = `${process.env.OWNER_BANK_ACCOUNT} - ${process.env.OWNER_BANK_NAME}`;
        break;
      case 'paypal':
        accountDetails = process.env.OWNER_PAYPAL_EMAIL;
        break;
    }
    
    const withdrawal = new OwnerWithdrawal({
      amount,
      method,
      accountDetails,
      notes
    });
    
    await withdrawal.save();
    
    // Auto-process withdrawal
    await processOwnerWithdrawal(withdrawal);
    
    res.json({ 
      message: 'Withdrawal request submitted successfully',
      withdrawal
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Owner Withdrawal History
router.get('/owner/withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = 'all' } = req.query;
    
    const filter = status !== 'all' ? { status } : {};
    
    const withdrawals = await OwnerWithdrawal.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await OwnerWithdrawal.countDocuments(filter);
    
    res.json({
      withdrawals,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Owner Withdrawal Summary
router.get('/owner/withdrawal-summary', authenticateAdmin, async (req, res) => {
  try {
    const ownerEarnings = await OwnerEarnings.findOne() || { totalEarnings: 0 };
    
    const [totalWithdrawn, pendingWithdrawals, thisMonthWithdrawals] = await Promise.all([
      OwnerWithdrawal.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      OwnerWithdrawal.countDocuments({ status: 'pending' }),
      OwnerWithdrawal.aggregate([
        { 
          $match: { 
            status: 'completed',
            completedAt: { 
              $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1) 
            }
          } 
        },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ])
    ]);
    
    const availableBalance = ownerEarnings.totalEarnings - (totalWithdrawn[0]?.total || 0);
    
    res.json({
      totalEarnings: ownerEarnings.totalEarnings,
      totalWithdrawn: totalWithdrawn[0]?.total || 0,
      availableBalance,
      pendingWithdrawals,
      thisMonthWithdrawals: thisMonthWithdrawals[0]?.total || 0,
      withdrawalLimits: {
        mpesa: process.env.MPESA_WITHDRAW_LIMIT || 70000,
        bank: process.env.BANK_WITHDRAW_LIMIT || 1000000,
        paypal: process.env.PAYPAL_WITHDRAW_LIMIT || 10000
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// M-Pesa Owner Withdrawal Callbacks
router.post('/owner/mpesa/result', async (req, res) => {
  try {
    const { Result } = req.body;
    
    if (Result.ResultCode === 0) {
      const withdrawal = await OwnerWithdrawal.findOne({
        transactionId: Result.ConversationID
      });
      
      if (withdrawal) {
        withdrawal.status = 'completed';
        withdrawal.completedAt = new Date();
        await withdrawal.save();
        
        // Deduct from owner earnings
        const ownerEarnings = await OwnerEarnings.findOne();
        if (ownerEarnings) {
          ownerEarnings.totalEarnings -= withdrawal.amount;
          await ownerEarnings.save();
        }
      }
    } else {
      const withdrawal = await OwnerWithdrawal.findOne({
        transactionId: Result.ConversationID
      });
      
      if (withdrawal) {
        withdrawal.status = 'failed';
        withdrawal.notes = Result.ResultDesc;
        await withdrawal.save();
      }
    }
    
    res.status(200).json({ message: 'Result received' });
  } catch (error) {
    console.error('M-Pesa result callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

router.post('/owner/mpesa/timeout', async (req, res) => {
  try {
    const { ConversationID } = req.body;
    
    const withdrawal = await OwnerWithdrawal.findOne({
      transactionId: ConversationID
    });
    
    if (withdrawal) {
      withdrawal.status = 'failed';
      withdrawal.notes = 'Transaction timed out';
      await withdrawal.save();
    }
    
    res.status(200).json({ message: 'Timeout received' });
  } catch (error) {
    console.error('M-Pesa timeout callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

// APP SETTINGS ROUTES

// Get App Settings
router.get('/settings', authenticateAdmin, async (req, res) => {
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
router.put('/settings', authenticateAdmin, async (req, res) => {
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

// MAINTENANCE & UTILITY ROUTES

// Reset App Data
router.post('/reset-app', authenticateAdmin, async (req, res) => {
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

// Export Data
router.get('/export/:type', authenticateAdmin, async (req, res) => {
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

// HELPER FUNCTIONS

// Owner Withdrawal Processing
async function processOwnerWithdrawal(withdrawal) {
  try {
    let result;
    
    switch (withdrawal.method) {
      case 'mpesa':
        result = await processOwnerMpesaWithdrawal(withdrawal);
        break;
      case 'bank':
        result = await processOwnerBankWithdrawal(withdrawal);
        break;
      case 'paypal':
        result = await processOwnerPayPalWithdrawal(withdrawal);
        break;
    }
    
    if (result.success) {
      withdrawal.status = 'completed';
      withdrawal.transactionId = result.transactionId;
      withdrawal.completedAt = new Date();
      
      // Deduct from owner earnings
      const ownerEarnings = await OwnerEarnings.findOne();
      if (ownerEarnings) {
        ownerEarnings.totalEarnings -= withdrawal.amount;
        await ownerEarnings.save();
      }
    } else {
      withdrawal.status = 'failed';
      withdrawal.notes = result.error;
    }
    
    await withdrawal.save();
    return result;
  } catch (error) {
    withdrawal.status = 'failed';
    withdrawal.notes = error.message;
    await withdrawal.save();
    throw error;
  }
}

async function processOwnerMpesaWithdrawal(withdrawal) {
  try {
    const response = await axios.post(
      `${process.env.MPESA_BASE_URL}/mpesa/b2c/v1/paymentrequest`,
      {
        InitiatorName: process.env.MPESA_INITIATOR_NAME,
        SecurityCredential: process.env.MPESA_SECURITY_CREDENTIAL,
        CommandID: 'BusinessPayment',
        Amount: withdrawal.amount,
        PartyA: process.env.MPESA_SHORTCODE,
        PartyB: withdrawal.accountDetails,
        Remarks: 'Owner withdrawal',
        QueueTimeOutURL: `${process.env.BASE_URL}/api/admin/owner/mpesa/timeout`,
        ResultURL: `${process.env.BASE_URL}/api/admin/owner/mpesa/result`,
        Occasion: 'Owner Withdrawal'
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.MPESA_ACCESS_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    return {
      success: true,
      transactionId: response.data.ConversationID
    };
  } catch (error) {
    return {
      success: false,
      error: `M-Pesa withdrawal failed: ${error.message}`
    };
  }
}

async function processOwnerBankWithdrawal(withdrawal) {
  try {
    const transactionId = `BANK-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // Log withdrawal for manual processing
    console.log(`Bank withdrawal requested: ${withdrawal.amount} to ${withdrawal.accountDetails}`);
    
    return {
      success: true,
      transactionId
    };
  } catch (error) {
    return {
      success: false,
      error: `Bank withdrawal failed: ${error.message}`
    };
  }
}

// Complete the processOwnerPayPalWithdrawal function
async function processOwnerPayPalWithdrawal(withdrawal) {
  try {
    const response = await axios.post(
      `${process.env.PAYPAL_BASE_URL}/v1/payments/payouts`,
      {
        sender_batch_header: {
          sender_batch_id: `owner-batch-${withdrawal._id}`,
          email_subject: 'Owner Withdrawal',
          email_message: 'Your withdrawal has been processed'
        },
        items: [{
          recipient_type: 'EMAIL',
          amount: {
            value: withdrawal.amount.toString(),
            currency: 'USD'
          },
          receiver: withdrawal.accountDetails,
          note: 'Owner withdrawal from WatchEarn',
          sender_item_id: `owner-item-${withdrawal._id}`
        }]
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.PAYPAL_ACCESS_TOKEN}`
        }
      }
    );
    
    return {
      success: true,
      transactionId: response.data.batch_header.payout_batch_id
    };
  } catch (error) {
    return {
      success: false,
      error: `PayPal withdrawal failed: ${error.message}`
    };
  }
}

// Regular Payment Processing Functions (already in your server but needed for router)
async function processMpesaPayment(payment) {
  try {
    const response = await axios.post(
      `${process.env.MPESA_BASE_URL}/mpesa/b2c/v1/paymentrequest`,
      {
        InitiatorName: process.env.MPESA_INITIATOR_NAME,
        SecurityCredential: process.env.MPESA_SECURITY_CREDENTIAL,
        CommandID: 'BusinessPayment',
        Amount: payment.amount,
        PartyA: process.env.MPESA_SHORTCODE,
        PartyB: payment.accountDetails,
        Remarks: 'Payment from WatchEarn',
        QueueTimeOutURL: `${process.env.BASE_URL}/api/payments/mpesa/timeout`,
        ResultURL: `${process.env.BASE_URL}/api/payments/mpesa/result`,
        Occasion: 'User Payment'
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

// Regular M-Pesa Payment Callbacks
router.post('/payments/mpesa/result', async (req, res) => {
  try {
    const { Result } = req.body;
    
    if (Result.ResultCode === 0) {
      const payment = await PaymentRequest.findOne({
        transactionId: Result.ConversationID
      });
      
      if (payment) {
        payment.status = 'approved';
        payment.processedAt = new Date();
        await payment.save();
        
        // Deduct from user balance
        const user = await User.findById(payment.userId);
        if (user) {
          user.balance -= payment.amount;
          await user.save();
        }
      }
    } else {
      const payment = await PaymentRequest.findOne({
        transactionId: Result.ConversationID
      });
      
      if (payment) {
        payment.status = 'failed';
        payment.notes = Result.ResultDesc;
        await payment.save();
      }
    }
    
    res.status(200).json({ message: 'Result received' });
  } catch (error) {
    console.error('M-Pesa result callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

router.post('/payments/mpesa/timeout', async (req, res) => {
  try {
    const { ConversationID } = req.body;
    
    const payment = await PaymentRequest.findOne({
      transactionId: ConversationID
    });
    
    if (payment) {
      payment.status = 'failed';
      payment.notes = 'Transaction timed out';
      await payment.save();
    }
    
    res.status(200).json({ message: 'Timeout received' });
  } catch (error) {
    console.error('M-Pesa timeout callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

// Admin Management Routes
router.get('/admins', authenticateAdmin, async (req, res) => {
  try {
    const admins = await Admin.find().select('-password');
    res.json(admins);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/admins', authenticateAdmin, async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    
    const existingAdmin = await Admin.findOne({ 
      $or: [{ username }, { email }] 
    });
    
    if (existingAdmin) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const admin = new Admin({
      username,
      email,
      password: hashedPassword,
      role: role || 'admin'
    });
    
    await admin.save();
    
    res.json({ 
      message: 'Admin created successfully',
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

router.delete('/admins/:id', authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findByIdAndDelete(req.params.id);
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    res.json({ message: 'Admin deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// System Health Check
router.get('/health', authenticateAdmin, async (req, res) => {
  try {
    const health = {
      status: 'healthy',
      timestamp: new Date(),
      database: 'connected',
      services: {
        mpesa: process.env.MPESA_BASE_URL ? 'configured' : 'not configured',
        paypal: process.env.PAYPAL_BASE_URL ? 'configured' : 'not configured',
        email: process.env.EMAIL_HOST ? 'configured' : 'not configured'
      },
      memory: process.memoryUsage(),
      uptime: process.uptime()
    };
    
    res.json(health);
  } catch (error) {
    res.status(500).json({ 
      status: 'unhealthy',
      error: error.message 
    });
  }
});

// Change Admin Password
router.patch('/change-password', authenticateAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const admin = await Admin.findById(req.admin._id);
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, admin.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedNewPassword;
    await admin.save();
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get System Statistics
router.get('/stats/system', authenticateAdmin, async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.countDocuments(),
      activeUsers: await User.countDocuments({
        lastActivity: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }),
      totalVideos: await Video.countDocuments(),
      totalViews: await WatchHistory.countDocuments(),
      totalPayments: await PaymentRequest.countDocuments(),
      pendingPayments: await PaymentRequest.countDocuments({ status: 'pending' }),
      approvedPayments: await PaymentRequest.countDocuments({ status: 'approved' }),
      rejectedPayments: await PaymentRequest.countDocuments({ status: 'rejected' }),
      totalEarnings: (await OwnerEarnings.findOne())?.totalEarnings || 0,
      todayEarnings: (await OwnerEarnings.findOne())?.todayEarnings || 0
    };
    
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Logout Admin
router.post('/logout', authenticateAdmin, async (req, res) => {
  try {
    // In a real implementation, you might want to blacklist the token
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;

// Payment Processing Functions
async function processMpesaPayment(payment) {
  try {
    // M-Pesa STK Push for user payments
    const response = await axios.post(
      `${process.env.MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
      {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: process.env.MPESA_PASSWORD,
        Timestamp: new Date().toISOString().replace(/[-:]/g, '').slice(0, 14),
        TransactionType: 'CustomerPayBillOnline',
        Amount: payment.amount,
        PartyA: payment.phoneNumber,
        PartyB: process.env.MPESA_SHORTCODE,
        PhoneNumber: payment.phoneNumber,
        CallBackURL: `${process.env.BASE_URL}/api/admin/mpesa/callback`,
        AccountReference: `WatchEarn-${payment._id}`,
        TransactionDesc: 'Payment withdrawal request'
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
      transactionId: response.data.CheckoutRequestID
    };
  } catch (error) {
    console.error('M-Pesa payment error:', error);
    return {
      success: false,
      error: `M-Pesa payment failed: ${error.message}`
    };
  }
}

async function processPayPalPayment(payment) {
  try {
    // PayPal Payout API
    const response = await axios.post(
      `${process.env.PAYPAL_BASE_URL}/v1/payments/payouts`,
      {
        sender_batch_header: {
          sender_batch_id: `batch-${payment._id}`,
          email_subject: 'You have a payout!',
          email_message: 'Your WatchEarn withdrawal has been processed'
        },
        items: [{
          recipient_type: 'EMAIL',
          amount: {
            value: payment.amount.toString(),
            currency: 'USD'
          },
          receiver: payment.email,
          note: 'WatchEarn withdrawal',
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

    return {
      success: true,
      transactionId: response.data.batch_header.payout_batch_id
    };
  } catch (error) {
    console.error('PayPal payment error:', error);
    return {
      success: false,
      error: `PayPal payment failed: ${error.message}`
    };
  }
}

// M-Pesa Callback Routes
router.post('/mpesa/callback', async (req, res) => {
  try {
    const { Body } = req.body;
    const { stkCallback } = Body;
    
    if (stkCallback.ResultCode === 0) {
      // Payment successful
      const checkoutRequestID = stkCallback.CheckoutRequestID;
      
      // Find payment by transaction ID
      const payment = await PaymentRequest.findOne({
        transactionId: checkoutRequestID
      });
      
      if (payment) {
        payment.status = 'completed';
        payment.completedAt = new Date();
        
        // Extract M-Pesa receipt number
        const callbackMetadata = stkCallback.CallbackMetadata;
        const receiptItem = callbackMetadata.Item.find(item => 
          item.Name === 'MpesaReceiptNumber'
        );
        
        if (receiptItem) {
          payment.mpesaReceiptNumber = receiptItem.Value;
        }
        
        await payment.save();
        
        // Deduct from user balance
        const user = await User.findById(payment.userId);
        if (user) {
          user.balance -= payment.amount;
          await user.save();
        }
      }
    } else {
      // Payment failed
      const checkoutRequestID = stkCallback.CheckoutRequestID;
      const payment = await PaymentRequest.findOne({
        transactionId: checkoutRequestID
      });
      
      if (payment) {
        payment.status = 'failed';
        payment.notes = stkCallback.ResultDesc;
        await payment.save();
      }
    }
    
    res.status(200).json({ message: 'Callback received' });
  } catch (error) {
    console.error('M-Pesa callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

// Additional utility routes
router.get('/system-health', authenticateAdmin, async (req, res) => {
  try {
    const mongoStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();
    
    // Check disk space for uploads
    const fs = require('fs');
    const path = require('path');
    const uploadDir = path.join(__dirname, '../uploads/videos');
    
    let diskSpace = 'unknown';
    try {
      const stats = fs.statSync(uploadDir);
      diskSpace = `${(stats.size / (1024 * 1024)).toFixed(2)} MB`;
    } catch (error) {
      diskSpace = 'directory not found';
    }
    
    res.json({
      status: 'healthy',
      timestamp: new Date(),
      database: mongoStatus,
      uptime: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`,
      memory: {
        used: `${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
        total: `${(memoryUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`
      },
      diskSpace
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin activity log
router.get('/activity-log', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    
    // This would require an ActivityLog model to be created
    // For now, we'll return recent admin actions from various collections
    const recentActions = await Promise.all([
      PaymentRequest.find({ status: { $ne: 'pending' } })
        .sort({ processedAt: -1 })
        .limit(20)
        .select('amount method status processedAt userId')
        .populate('userId', 'email'),
      
      Video.find()
        .sort({ uploadedAt: -1 })
        .limit(10)
        .select('title uploadedAt size'),
      
      User.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .select('email createdAt balance')
    ]);
    
    const [payments, videos, users] = recentActions;
    
    const activityLog = [
      ...payments.map(p => ({
        type: 'payment',
        action: `Payment ${p.status}`,
        details: `${p.amount} via ${p.method} for ${p.userId?.email}`,
        timestamp: p.processedAt || p.createdAt
      })),
      ...videos.map(v => ({
        type: 'video',
        action: 'Video uploaded',
        details: `${v.title} (${(v.size / (1024 * 1024)).toFixed(2)} MB)`,
        timestamp: v.uploadedAt
      })),
      ...users.map(u => ({
        type: 'user',
        action: 'User registered',
        details: `${u.email} (Balance: ${u.balance})`,
        timestamp: u.createdAt
      }))
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
     .slice(0, limit);
    
    res.json({
      activityLog,
      total: activityLog.length,
      page: parseInt(page)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Batch user operations
router.post('/users/batch-update', authenticateAdmin, async (req, res) => {
  try {
    const { operation, userIds, value } = req.body;
    
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }
    
    let updateQuery = {};
    let updateDescription = '';
    
    switch (operation) {
      case 'activate':
        updateQuery = { isActive: true };
        updateDescription = 'activated';
        break;
      case 'deactivate':
        updateQuery = { isActive: false };
        updateDescription = 'deactivated';
        break;
      case 'setBalance':
        updateQuery = { balance: parseFloat(value) || 0 };
        updateDescription = `balance set to ${value}`;
        break;
      case 'addBalance':
        updateQuery = { $inc: { balance: parseFloat(value) || 0 } };
        updateDescription = `balance increased by ${value}`;
        break;
      case 'resetWatchTime':
        updateQuery = { watchTime: 0 };
        updateDescription = 'watch time reset';
        break;
      default:
        return res.status(400).json({ error: 'Invalid operation' });
    }
    
    const result = await User.updateMany(
      { _id: { $in: userIds } },
      updateQuery
    );
    
    res.json({
      message: `${result.modifiedCount} users ${updateDescription}`,
      affectedUsers: result.modifiedCount
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Video analytics
router.get('/videos/:id/analytics', authenticateAdmin, async (req, res) => {
  try {
    const videoId = req.params.id;
    
    const video = await Video.findById(videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const analytics = await WatchHistory.aggregate([
      { $match: { videoId: mongoose.Types.ObjectId(videoId) } },
      {
        $group: {
          _id: null,
          totalViews: { $sum: 1 },
          totalWatchTime: { $sum: '$watchTime' },
          avgWatchTime: { $avg: '$watchTime' },
          uniqueViewers: { $addToSet: '$userId' }
        }
      },
      {
        $project: {
          totalViews: 1,
          totalWatchTime: 1,
          avgWatchTime: 1,
          uniqueViewers: { $size: '$uniqueViewers' }
        }
      }
    ]);
    
    const viewsByDay = await WatchHistory.aggregate([
      { $match: { videoId: mongoose.Types.ObjectId(videoId) } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          views: { $sum: 1 },
          watchTime: { $sum: '$watchTime' }
        }
      },
      { $sort: { _id: -1 } },
      { $limit: 30 }
    ]);
    
    res.json({
      video: {
        id: video._id,
        title: video.title,
        duration: video.duration,
        uploadedAt: video.uploadedAt
      },
      analytics: analytics[0] || {
        totalViews: 0,
        totalWatchTime: 0,
        avgWatchTime: 0,
        uniqueViewers: 0
      },
      viewsByDay: viewsByDay.reverse()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Generate reports
router.get('/reports/:type', authenticateAdmin, async (req, res) => {
  try {
    const { type } = req.params;
    const { startDate, endDate } = req.query;
    
    const dateFilter = {};
    if (startDate && endDate) {
      dateFilter.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    let report = {};
    
    switch (type) {
      case 'earnings':
        const earningsData = await OwnerEarnings.findOne();
        const withdrawals = await OwnerWithdrawal.find(dateFilter);
        
        report = {
          totalEarnings: earningsData?.totalEarnings || 0,
          todayEarnings: earningsData?.todayEarnings || 0,
          totalWithdrawals: withdrawals.reduce((sum, w) => sum + w.amount, 0),
          withdrawalCount: withdrawals.length,
          averageWithdrawal: withdrawals.length > 0 ? 
            withdrawals.reduce((sum, w) => sum + w.amount, 0) / withdrawals.length : 0
        };
        break;
        
      case 'users':
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ 
          lastActivity: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        });
        const newUsers = await User.countDocuments(dateFilter);
        
        report = {
          totalUsers,
          activeUsers,
          newUsers,
          activityRate: ((activeUsers / totalUsers) * 100).toFixed(2) + '%'
        };
        break;
        
      case 'videos':
        const totalVideos = await Video.countDocuments();
        const totalViews = await WatchHistory.countDocuments(dateFilter);
        const avgViewsPerVideo = totalVideos > 0 ? (totalViews / totalVideos).toFixed(2) : 0;
        
        report = {
          totalVideos,
          totalViews,
          avgViewsPerVideo,
          newVideos: await Video.countDocuments(dateFilter)
        };
        break;
        
      default:
        return res.status(400).json({ error: 'Invalid report type' });
    }
    
    res.json({
      reportType: type,
      dateRange: { startDate, endDate },
      generatedAt: new Date(),
      data: report
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Clean up old data
router.post('/cleanup', authenticateAdmin, async (req, res) => {
  try {
    const { type, days = 30 } = req.body;
    const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    
    let result = {};
    
    switch (type) {
      case 'watch-history':
        result = await WatchHistory.deleteMany({ createdAt: { $lt: cutoffDate } });
        break;
      case 'completed-payments':
        result = await PaymentRequest.deleteMany({ 
          status: 'completed',
          processedAt: { $lt: cutoffDate }
        });
        break;
      case 'failed-payments':
        result = await PaymentRequest.deleteMany({ 
          status: 'failed',
          createdAt: { $lt: cutoffDate }
        });
        break;
      default:
        return res.status(400).json({ error: 'Invalid cleanup type' });
    }
    
    res.json({
      message: `Cleanup completed for ${type}`,
      deletedCount: result.deletedCount,
      cutoffDate
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;

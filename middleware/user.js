const express = require('express');
const { User, AppSettings, OwnerEarnings } = require('../models');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get User Profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Online Time and Earnings
router.post('/update-activity', authenticateToken, async (req, res) => {
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

module.exports = router;

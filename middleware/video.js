const express = require('express');
const path = require('path');
const { Video, User, WatchHistory, AppSettings, OwnerEarnings } = require('../models');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get Videos
router.get('/', authenticateToken, async (req, res) => {
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
router.post('/:id/watch', authenticateToken, async (req, res) => {
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

// Video Streaming Endpoint
router.get('/:id/stream', authenticateToken, async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    const videoPath = path.join(__dirname, '../uploads', 'videos', video.filename);
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
        'Content-Range

const mongoose = require('mongoose');

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

module.exports = mongoose.model('OwnerEarnings', ownerEarningsSchema);

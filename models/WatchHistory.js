const mongoose = require('mongoose');

const watchHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  videoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Video', required: true },
  watchedDuration: { type: Number, required: true }, // in seconds
  earnedAmount: { type: Number, default: 0 },
  watchedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('WatchHistory', watchHistorySchema);

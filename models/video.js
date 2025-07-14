const mongoose = require('mongoose');

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

module.exports = mongoose.model('Video', videoSchema);

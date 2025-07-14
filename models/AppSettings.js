const mongoose = require('mongoose');

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

module.exports = mongoose.model('AppSettings', appSettingsSchema);

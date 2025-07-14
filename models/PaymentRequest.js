const mongoose = require('mongoose');

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

module.exports = mongoose.model('PaymentRequest', paymentRequestSchema);

const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  zitadelId: {
    type: String,
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  balance: {
    type: Number,
    default: 10000,
    min: 0
  },
  gamesPlayed: {
    type: Number,
    default: 0
  },
  totalWins: {
    type: Number,
    default: 0
  },
  totalLosses: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  }
});

// Index für schnelle Leaderboard-Abfragen
UserSchema.index({ balance: -1 });

module.exports = mongoose.model('User', UserSchema);

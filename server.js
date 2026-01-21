const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // Neu: Für Pfade
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
// WICHTIG: Nutze process.env.MONGODB_URI für die Sicherheit!
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://helinoCasinoUser:HelinoCasino176237@193.23.160.211:27020/helinocasino?authSource=admin';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB verbunden!'))
  .catch(err => {
    console.error('❌ MongoDB Fehler:', err);
    mongoose.connect('mongodb://localhost:27017/casino')
      .then(() => console.log('✅ Lokale MongoDB verbunden'))
      .catch(err2 => console.error('❌ Keine MongoDB Verbindung möglich:', err2));
  });

// Wir nutzen das Modell aus der separaten Datei oder definieren es hier einmalig sauber
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 10000 },
  gamesPlayed: { type: Number, default: 0 },
  totalWins: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

// Falls das Model schon existiert, nutzen wir es, sonst neu erstellen
const User = mongoose.models.User || mongoose.model('User', userSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'casino-secret-key-123';

// Middleware zum Prüfen des Tokens
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Kein Token vorhanden' });

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.userId = user.userId;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Ungültiges Token' });
  }
};

// API ROUTES
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) return res.status(400).json({ error: 'Username oder Email bereits vergeben' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword, balance: 10000 });
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user._id, username: user.username, balance: user.balance } });
  } catch (error) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Anmeldedaten ungültig' });
    }
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user._id, username: user.username, balance: user.balance } });
  } catch (error) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/balance/update', authenticateToken, async (req, res) => {
  try {
    const { amount, win } = req.body;
    const user = await User.findById(req.userId);
    user.balance += amount;
    user.gamesPlayed += 1;
    if (win) user.totalWins += 1;
    await user.save();
    res.json({ success: true, newBalance: user.balance });
  } catch (error) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const topUsers = await User.find().sort({ balance: -1 }).limit(10).select('username balance');
    res.json({ success: true, leaderboard: topUsers });
  } catch (error) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// STATISCHE DATEIEN SERVIEREN
// WICHTIG: Deine HTML/CSS/JS Dateien müssen im Ordner "public" liegen
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🎰 Casino Server läuft auf Port ${PORT}`);
});

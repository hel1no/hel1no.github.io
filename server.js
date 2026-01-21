const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://helinoCasinoUser:HelinoCasino176237@193.23.160.211:27020/helinocasino?authSource=admin';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB verbunden!'))
  .catch(err => {
    console.error('❌ MongoDB Fehler:', err);
    mongoose.connect('mongodb://localhost:27017/casino')
      .then(() => console.log('✅ Lokale MongoDB verbunden'))
      .catch(err2 => console.error('❌ Keine MongoDB Verbindung möglich:', err2));
  });

// Statistik-Model
const statsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  gamesPlayed: { type: Number, default: 0 },
  gamesWon: { type: Number, default: 0 },
  totalWon: { type: Number, default: 0 },
  totalLost: { type: Number, default: 0 },
  biggestWin: { type: Number, default: 0 },
  favoriteGame: { type: String, default: 'slot' },
  lastPlayed: { type: Date, default: Date.now }
});

const Stats = mongoose.model('Stats', statsSchema);

// User Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 10000 },
  gamesPlayed: { type: Number, default: 0 },
  totalWins: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  stats: { type: mongoose.Schema.Types.ObjectId, ref: 'Stats' }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'casino-secret-key-123';

// Auth Middleware
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

    // 1. User Objekt erstellen und speichern, um eine ID zu generieren
    const user = new User({
      username,
      email,
      password: hashedPassword,
      balance: 10000
    });
    await user.save();

    // 2. Stats erstellen und mit der soeben erstellten User-ID verknüpfen
    const stats = new Stats({
      userId: user._id
    });
    await stats.save();

    // 3. User updaten, um die Stats-Referenz zu speichern
    user.stats = stats._id;
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        balance: user.balance
      }
    });
  } catch (error) {
    console.error('Registrierungsfehler:', error);
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
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        balance: user.balance
      }
    });
  } catch (error) {
    console.error('Login Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }
    res.json({ success: true, user });
  } catch (error) {
    console.error('User Fetch Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// Stats API Route
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await Stats.findOne({ userId: req.userId });
    if (!stats) {
      // Stats erstellen falls nicht vorhanden
      const newStats = new Stats({ userId: req.userId });
      await newStats.save();

      // User updaten
      await User.findByIdAndUpdate(req.userId, { stats: newStats._id });

      return res.json({ success: true, stats: newStats });
    }
    res.json({ success: true, stats });
  } catch (error) {
    console.error('Stats Fetch Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// Update Balance mit Stats
app.post('/api/balance/update', authenticateToken, async (req, res) => {
  try {
    const { amount, gameType, win } = req.body;
    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    user.balance += amount;
    user.gamesPlayed += 1;

    // Stats aktualisieren oder erstellen
    let stats = await Stats.findOne({ userId: req.userId });
    if (!stats) {
      stats = new Stats({ userId: req.userId });
      user.stats = stats._id;
    }

    stats.gamesPlayed += 1;

    if (win && amount > 0) {
      user.totalWins += 1;
      stats.gamesWon += 1;
      stats.totalWon += amount;

      if (amount > stats.biggestWin) {
        stats.biggestWin = amount;
      }
    } else if (amount < 0) {
      stats.totalLost += Math.abs(amount);
    }

    stats.lastPlayed = new Date();
    await stats.save();
    await user.save();

    res.json({
      success: true,
      newBalance: user.balance,
      stats: {
        gamesPlayed: stats.gamesPlayed,
        gamesWon: stats.gamesWon,
        totalWon: stats.totalWon,
        totalLost: stats.totalLost,
        biggestWin: stats.biggestWin
      }
    });
  } catch (error) {
    console.error('Balance Update Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// Leaderboard mit Stats
app.get('/api/leaderboard', async (req, res) => {
  try {
    const topUsers = await User.find()
      .sort({ balance: -1 })
      .limit(10)
      .select('username balance gamesPlayed totalWins')
      .populate('stats');

    const leaderboard = topUsers.map(user => ({
      username: user.username,
      balance: user.balance,
      gamesPlayed: user.gamesPlayed || 0,
      totalWins: user.totalWins || 0,
      stats: user.stats ? {
        gamesWon: user.stats.gamesWon || 0,
        totalWon: user.stats.totalWon || 0
      } : null
    }));

    res.json({ success: true, leaderboard });
  } catch (error) {
    console.error('Leaderboard Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// Freundschafts-Model
const friendSchema = new mongoose.Schema({
  user1: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  user2: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, enum: ['pending', 'accepted', 'blocked'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const Friend = mongoose.model('Friend', friendSchema);

// Chat-Nachricht-Model
const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

// Spielraum-Model
const roomSchema = new mongoose.Schema({
  name: { type: String, required: true },
  creator: { type: String, required: true },
  gameType: { type: String, default: 'blackjack' },
  players: [{ type: String }],
  maxPlayers: { type: Number, default: 6 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const Room = mongoose.model('Room', roomSchema);

// Freundes-API
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const friends = await Friend.find({
      $or: [
        { user1: req.userId, status: 'accepted' },
        { user2: req.userId, status: 'accepted' }
      ]
    }).populate('user1 user2');

    const friendList = friends.map(f => {
      const friend = f.user1._id.toString() === req.userId ? f.user2 : f.user1;
      return {
        username: friend.username,
        balance: friend.balance
      };
    });

    res.json({ success: true, friends: friendList });
  } catch (error) {
    console.error('Friends Fetch Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/friends/add', authenticateToken, async (req, res) => {
  try {
    const { friendUsername } = req.body;
    const friend = await User.findOne({ username: friendUsername });

    if (!friend) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    if (friend._id.toString() === req.userId) {
      return res.status(400).json({ error: 'Du kannst nicht dich selbst hinzufügen' });
    }

    const existingRequest = await Friend.findOne({
      $or: [
        { user1: req.userId, user2: friend._id },
        { user1: friend._id, user2: req.userId }
      ]
    });

    if (existingRequest) {
      return res.status(400).json({ error: 'Freundschaftsanfrage bereits vorhanden' });
    }

    await Friend.create({
      user1: req.userId,
      user2: friend._id,
      status: 'pending'
    });

    res.json({ success: true, message: 'Freundschaftsanfrage gesendet' });
  } catch (error) {
    console.error('Add Friend Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// Chat-API
app.get('/api/chat/messages', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { receiver: null }, // Öffentliche Nachrichten
        { sender: (await User.findById(req.userId)).username },
        { receiver: (await User.findById(req.userId)).username }
      ]
    }).sort({ timestamp: -1 }).limit(50);

    res.json({ success: true, messages });
  } catch (error) {
    console.error('Chat Messages Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/chat/send', authenticateToken, async (req, res) => {
  try {
    const { message, receiver } = req.body;
    const user = await User.findById(req.userId);

    if (!message || message.trim().length === 0) {
      return res.status(400).json({ error: 'Nachricht darf nicht leer sein' });
    }

    const chatMessage = new Message({
      sender: user.username,
      receiver: receiver || null,
      message: message.trim()
    });

    await chatMessage.save();

    res.json({ success: true, message: chatMessage });
  } catch (error) {
    console.error('Send Message Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// Room-API
app.get('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const rooms = await Room.find({ isActive: true });
    res.json({ success: true, rooms });
  } catch (error) {
    console.error('Rooms Fetch Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/rooms/create', authenticateToken, async (req, res) => {
  try {
    const { name, gameType } = req.body;
    const user = await User.findById(req.userId);

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Raumname darf nicht leer sein' });
    }

    const room = new Room({
      name: name.trim(),
      creator: user.username,
      gameType: gameType || 'blackjack',
      players: [user.username]
    });

    await room.save();

    res.json({ success: true, room });
  } catch (error) {
    console.error('Create Room Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/rooms/join', authenticateToken, async (req, res) => {
  try {
    const { roomId } = req.body;
    const user = await User.findById(req.userId);

    const room = await Room.findById(roomId);
    if (!room) {
      return res.status(404).json({ error: 'Raum nicht gefunden' });
    }

    if (room.players.length >= room.maxPlayers) {
      return res.status(400).json({ error: 'Raum ist bereits voll' });
    }

    if (room.players.includes(user.username)) {
      return res.status(400).json({ error: 'Du bist bereits im Raum' });
    }

    room.players.push(user.username);
    await room.save();

    res.json({ success: true, room });
  } catch (error) {
    console.error('Join Room Fehler:', error);
    res.status(500).json({ error: 'Server Fehler' });
  }
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// WebSocket Connection
io.on('connection', (socket) => {
  console.log('Neue WebSocket-Verbindung:', socket.id);

  socket.on('auth', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);

      if (user) {
        socket.user = user;
        socket.join('global');
        console.log(`User ${user.username} hat sich mit WebSocket verbunden`);

        socket.emit('auth_success', { username: user.username });

        // Sende Chat-Historie
        const messages = await Message.find({ receiver: null })
          .sort({ timestamp: -1 })
          .limit(50);
        socket.emit('chat_history', messages.reverse());
      }
    } catch (error) {
      console.error('WebSocket Auth Fehler:', error);
    }
  });

  socket.on('chat_message', async (data) => {
    try {
      if (!socket.user || !data.message || data.message.trim().length === 0) return;

      const chatMessage = new Message({
        sender: socket.user.username,
        receiver: data.receiver || null,
        message: data.message.trim()
      });

      await chatMessage.save();

      // Broadcast Nachricht
      if (data.receiver) {
        // Private Nachricht
        io.to(data.receiver).emit('chat_message', chatMessage);
        socket.emit('chat_message', chatMessage);
      } else {
        // Öffentliche Nachricht
        io.to('global').emit('chat_message', chatMessage);
      }
    } catch (error) {
      console.error('WebSocket Chat Fehler:', error);
    }
  });

  socket.on('create_room', async (data) => {
    try {
      if (!socket.user) return;

      const room = new Room({
        name: data.name,
        creator: socket.user.username,
        gameType: data.gameType || 'blackjack',
        players: [socket.user.username]
      });

      await room.save();

      socket.join(`room_${room._id}`);

      // Broadcast Raum-Update
      const rooms = await Room.find({ isActive: true });
      io.to('global').emit('rooms_update', rooms);
    } catch (error) {
      console.error('WebSocket Create Room Fehler:', error);
    }
  });

  socket.on('join_room', async (data) => {
    try {
      if (!socket.user) return;

      const room = await Room.findById(data.roomId);
      if (!room || room.players.length >= room.maxPlayers) return;

      if (!room.players.includes(socket.user.username)) {
        room.players.push(socket.user.username);
        await room.save();

        socket.join(`room_${room._id}`);

        // Nachricht an Raum senden
        io.to(`room_${room._id}`).emit('room_message', {
          type: 'join',
          user: socket.user.username,
          message: `${socket.user.username} ist dem Raum beigetreten`
        });

        // Broadcast Raum-Update
        const rooms = await Room.find({ isActive: true });
        io.to('global').emit('rooms_update', rooms);
      }
    } catch (error) {
      console.error('WebSocket Join Room Fehler:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('WebSocket getrennt:', socket.id);
  });
});

// STATISCHE DATEIEN SERVIEREN
app.use(express.static(__dirname));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🎰 Casino Server läuft auf Port ${PORT} (mit WebSocket Support)`);
});

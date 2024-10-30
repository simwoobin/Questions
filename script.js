const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const socketio = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = socketio(server);

app.use(express.json());
app.use(cors());

// Connect to MongoDB (Assuming local instance for simplicity)
mongoose.connect('mongodb://localhost:27017/qna_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define MongoDB Schema and Models (User, Question, Answer)

const userSchema = new mongoose.Schema({
  username: String,
  passwordHash: String,
});

const questionSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  sectionId: String,
  text: String,
  image: String,
  answers: [{
    userId: mongoose.Schema.Types.ObjectId,
    text: String,
    image: String,
    starRating: Number,
  }],
});

const User = mongoose.model('User', userSchema);
const Question = mongoose.model('Question', questionSchema);

// User Authentication Endpoints

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const newUser = new User({ username, passwordHash });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (await bcrypt.compare(password, user.passwordHash)) {
      const token = jwt.sign({ userId: user._id }, 'your_secret_key_here');
      res.json({ token });
    } else {
      res.status(401).json({ message: 'Authentication failed' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Questions and Answers Endpoints

// Get all questions
app.get('/api/questions', async (req, res) => {
  try {
    const questions = await Question.find().populate('userId', 'username');
    res.json(questions);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Post a question
app.post('/api/questions', authenticateUser, async (req, res) => {
  const { sectionId, text, image } = req.body;
  const userId = req.user.userId;

  try {
    const newQuestion = new Question({ userId, sectionId, text, image, answers: [] });
    await newQuestion.save();
    res.status(201).json(newQuestion);
    io.emit('newQuestion', newQuestion); // Emit event to update all clients
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Post an answer
app.post('/api/questions/:id/answers', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { text, image } = req.body;
  const userId = req.user.userId;

  try {
    const question = await Question.findById(id);

    if (!question) {
      return res.status(404).json({ message: 'Question not found' });
    }

    const newAnswer = { userId, text, image };
    question.answers.push(newAnswer);
    await question.save();
    res.status(201).json(newAnswer);
    io.emit('newAnswer', { questionId: id, answer: newAnswer }); // Emit event to update all clients
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete a question
app.delete('/api/questions/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId;

  try {
    const question = await Question.findById(id);

    if (!question) {
      return res.status(404).json({ message: 'Question not found' });
    }

    if (question.userId.toString() !== userId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    await question.remove();
    res.json({ message: 'Question deleted' });
    io.emit('deleteQuestion', id); // Emit event to update all clients
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Middleware to authenticate user using JWT
function authenticateUser(req, res, next) {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, 'your_secret_key_here');
    req.user = { userId: decoded.userId };
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// Start Server
const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Server started on port ${port}`));

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = 'your_secret_key_here'; // Change this to a secure key in production

app.use(cors());
app.use(bodyParser.json());

// Initialize SQLite database
const db = new sqlite3.Database(path.resolve(__dirname, 'classroom.db'), (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create tables if not exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS classes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    teacher_id INTEGER,
    FOREIGN KEY (teacher_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    class_id INTEGER,
    title TEXT,
    description TEXT,
    due_date TEXT,
    FOREIGN KEY (class_id) REFERENCES classes(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER,
    student_id INTEGER,
    content TEXT,
    grade TEXT,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id),
    FOREIGN KEY (student_id) REFERENCES users(id)
  )`);
});

// Helper function to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Routes

// Register user
app.post('/api/register', (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ message: 'Username, password and role are required' });
  }
  const hashedPassword = bcrypt.hashSync(password, 8);
  const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
  db.run(sql, [username, hashedPassword, role], function(err) {
    if (err) {
      return res.status(500).json({ message: 'User registration failed', error: err.message });
    }
    res.status(201).json({ id: this.lastID, username, role });
  });
});

// Login user
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const sql = 'SELECT * FROM users WHERE username = ?';
  db.get(sql, [username], (err, user) => {
    if (err) return res.status(500).json({ message: 'Login failed', error: err.message });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) return res.status(401).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ token });
  });
});

// Get classes for user
app.get('/api/classes', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;

  if (userRole === 'teacher') {
    const sql = 'SELECT * FROM classes WHERE teacher_id = ?';
    db.all(sql, [userId], (err, rows) => {
      if (err) return res.status(500).json({ message: 'Failed to get classes', error: err.message });
      res.json(rows);
    });
  } else if (userRole === 'student') {
    // For simplicity, students see all classes (enrollment not implemented yet)
    const sql = 'SELECT * FROM classes';
    db.all(sql, [], (err, rows) => {
      if (err) return res.status(500).json({ message: 'Failed to get classes', error: err.message });
      res.json(rows);
    });
  } else {
    res.status(403).json({ message: 'Invalid role' });
  }
});

// Create class (teacher only)
app.post('/api/classes', authenticateToken, (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Only teachers can create classes' });
  const { name, description } = req.body;
  const sql = 'INSERT INTO classes (name, description, teacher_id) VALUES (?, ?, ?)';
  db.run(sql, [name, description, req.user.id], function(err) {
    if (err) return res.status(500).json({ message: 'Failed to create class', error: err.message });
    res.status(201).json({ id: this.lastID, name, description, teacher_id: req.user.id });
  });
});

// Get assignments for a class
app.get('/api/classes/:classId/assignments', authenticateToken, (req, res) => {
  const classId = req.params.classId;
  const sql = 'SELECT * FROM assignments WHERE class_id = ?';
  db.all(sql, [classId], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to get assignments', error: err.message });
    res.json(rows);
  });
});

// Create assignment (teacher only)
app.post('/api/classes/:classId/assignments', authenticateToken, (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Only teachers can create assignments' });
  const classId = req.params.classId;
  const { title, description, due_date } = req.body;
  const sql = 'INSERT INTO assignments (class_id, title, description, due_date) VALUES (?, ?, ?, ?)';
  db.run(sql, [classId, title, description, due_date], function(err) {
    if (err) return res.status(500).json({ message: 'Failed to create assignment', error: err.message });
    res.status(201).json({ id: this.lastID, class_id: classId, title, description, due_date });
  });
});

// Submit assignment (student only)
app.post('/api/assignments/:assignmentId/submissions', authenticateToken, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Only students can submit assignments' });
  const assignmentId = req.params.assignmentId;
  const { content } = req.body;
  const sql = 'INSERT INTO submissions (assignment_id, student_id, content) VALUES (?, ?, ?)';
  db.run(sql, [assignmentId, req.user.id, content], function(err) {
    if (err) return res.status(500).json({ message: 'Failed to submit assignment', error: err.message });
    res.status(201).json({ id: this.lastID, assignment_id: assignmentId, student_id: req.user.id, content });
  });
});

// Get submissions for an assignment (teacher only)
app.get('/api/assignments/:assignmentId/submissions', authenticateToken, (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Only teachers can view submissions' });
  const assignmentId = req.params.assignmentId;
  const sql = `SELECT submissions.*, users.username AS student_name 
               FROM submissions 
               JOIN users ON submissions.student_id = users.id 
               WHERE assignment_id = ?`;
  db.all(sql, [assignmentId], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to get submissions', error: err.message });
    res.json(rows);
  });
});

// Grade submission (teacher only)
app.put('/api/submissions/:submissionId/grade', authenticateToken, (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Only teachers can grade submissions' });
  const submissionId = req.params.submissionId;
  const { grade } = req.body;
  const sql = 'UPDATE submissions SET grade = ? WHERE id = ?';
  db.run(sql, [grade, submissionId], function(err) {
    if (err) return res.status(500).json({ message: 'Failed to grade submission', error: err.message });
    res.json({ message: 'Submission graded' });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

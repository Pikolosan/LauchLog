const express = require('express');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
// Require JWT_SECRET from environment for security
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET environment variable is required for security');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'LaunchLog API is running' });
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    },
  },
}));

// Rate limiting - More lenient for development
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Increased for development use
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Increased from 5 to 50 for development
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting
app.use('/api/', globalLimiter);
app.use('/api/auth/', authLimiter);

// Compression and parsing middleware
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Data sanitization against NoSQL query injection
// Note: Using manual validation in routes instead of middleware due to compatibility issues
// app.use(mongoSanitize());

// Configure CORS with specific origins
const allowedOrigins = [
  'http://localhost:5000',
  'http://127.0.0.1:5000',
  'https://localhost:5000',
  'http://localhost:3000',
  // Explicit frontend URL from environment
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (same-origin or mobile apps)
    if (!origin) return callback(null, true);
    
    // Check exact matches for development
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    }
    
    // For production platforms, allow common deployment domains
    if (origin.endsWith('.replit.app') || origin.endsWith('.replit.dev') || 
        origin.endsWith('.onrender.com') || origin.endsWith('.vercel.app') || 
        origin.endsWith('.netlify.app') || origin.endsWith('.herokuapp.com')) {
      return callback(null, true);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Trust proxy for rate limiting to work correctly in Replit
app.set('trust proxy', 1);

// Serve static files from React build in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'dist')));
}

// MongoDB connection
let db;
let isConnected = false;
let client = null;

// Only create MongoDB client if connection string is provided
if (process.env.MONGODB_CONNECTION_STRING) {
  client = new MongoClient(process.env.MONGODB_CONNECTION_STRING, {
    serverApi: {
      version: '1',
      strict: true,
      deprecationErrors: true,
    }
  });
}

async function connectToDatabase() {
  if (!client) {
    console.log('⚠️ No MongoDB connection string provided - running in fallback mode');
    isConnected = false;
    return;
  }
  
  try {
    await client.connect();
    await client.db('admin').command({ ping: 1 });
    db = client.db('launchlog');
    isConnected = true;
    console.log('✅ Connected to MongoDB Atlas');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    console.log('⚠️ Running in fallback mode - data will not persist');
    isConnected = false;
  }
}

// Authentication Routes

// Password validation function
const validatePassword = (password) => {
  const errors = [];
  
  if (password.length < 12) {
    errors.push('Password must be at least 12 characters long');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  // Check for common weak passwords
  const commonPasswords = ['123456789012', 'password1234', 'admin1234567', 'welcome12345'];
  if (commonPasswords.some(common => password.toLowerCase().includes(common.toLowerCase()))) {
    errors.push('Password is too common or weak');
  }
  
  return errors;
};

// Register user
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail().isLength({ max: 254 }),
  body('name').trim().isLength({ min: 2, max: 50 }).matches(/^[a-zA-Z\s]+$/),
  body('password').custom((password) => {
    const errors = validatePassword(password);
    if (errors.length > 0) {
      throw new Error(errors.join(', '));
    }
    return true;
  })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;

    // Check if user already exists
    if (isConnected) {
      const existingUser = await db.collection('users').findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }
    } else {
      // Check fallback storage
      const existingUser = fallbackUsers.find(user => user.email === email);
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }
    }

    // Hash password with higher cost for better security
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = {
      email,
      password: hashedPassword,
      name,
      role: email === process.env.ADMIN_EMAIL ? 'admin' : 'user', // Admin email from environment
      createdAt: new Date(),
      emailVerified: false // Add email verification status
    };

    let userId;
    if (isConnected) {
      const result = await db.collection('users').insertOne(newUser);
      userId = result.insertedId.toString();
    } else {
      userId = Date.now().toString();
      newUser.id = userId;
      fallbackUsers.push(newUser);
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId, email, name, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '15m' } // Consistent with login token expiry
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: userId, email, name, role: newUser.role }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login user
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Find user
    let user;
    if (isConnected) {
      user = await db.collection('users').findOne({ email });
    } else {
      user = fallbackUsers.find(u => u.email === email);
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const userId = user.id || user._id.toString();
    const userRole = user.role || 'user'; // No auto-promotion - security fix
    
    const token = jwt.sign(
      { userId, email: user.email, name: user.name, role: userRole },
      JWT_SECRET,
      { expiresIn: '15m' } // Shorter token expiry for better security
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: userId, email: user.email, name: user.name, role: userRole }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin Routes

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    if (isConnected) {
      const users = await db.collection('users').find({}, { projection: { password: 0 } }).toArray();
      res.json(users);
    } else {
      // Return fallback users without passwords
      const safeUsers = fallbackUsers.map(user => {
        const { password, ...safeUser } = user;
        return safeUser;
      });
      res.json(safeUsers);
    }
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get user stats (admin only)
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    let totalUsers = 0;
    let totalSessions = 0;
    let totalTasks = 0;

    if (isConnected) {
      totalUsers = await db.collection('users').countDocuments();
      const allUserData = await db.collection('userData').find({}).toArray();
      totalSessions = allUserData.reduce((sum, user) => sum + (user.timerSessions?.length || 0), 0);
      totalTasks = allUserData.reduce((sum, user) => {
        const tasks = user.tasks || { todo: [], doing: [], done: [] };
        return sum + tasks.todo.length + tasks.doing.length + tasks.done.length;
      }, 0);
    } else {
      totalUsers = fallbackUsers.length;
      Object.values(fallbackData).forEach(userData => {
        if (userData.timerSessions) totalSessions += userData.timerSessions.length;
        if (userData.tasks) {
          totalTasks += userData.tasks.todo.length + userData.tasks.doing.length + userData.tasks.done.length;
        }
      });
    }

    res.json({
      totalUsers,
      totalSessions,
      totalTasks,
      systemStatus: isConnected ? 'MongoDB Connected' : 'Fallback Mode'
    });
  } catch (error) {
    console.error('Error fetching admin stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (isConnected) {
      await db.collection('users').deleteOne({ _id: new require('mongodb').ObjectId(userId) });
      await db.collection('userData').deleteOne({ userId });
    } else {
      // Remove from fallback storage
      const userIndex = fallbackUsers.findIndex(user => user.id === userId);
      if (userIndex > -1) {
        fallbackUsers.splice(userIndex, 1);
      }
      delete fallbackData[userId];
    }
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// API Routes

// In-memory fallback storage for users
let fallbackUsers = [];

// In-memory fallback storage
let fallbackData = {
  userId: 'default',
  timerSessions: [],
  tasks: { todo: [], doing: [], done: [] },
  jobs: [],
  subjects: ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'],
  dashboardData: {
    totalHours: 0,
    completedTasks: 0,
    activeApplications: 0,
    sessionsThisWeek: 0
  }
};

// Get user data
app.get('/api/user-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    if (!isConnected) {
      // Return user-specific fallback data
      if (!fallbackData[userId]) {
        fallbackData[userId] = {
          userId,
          timerSessions: [],
          tasks: { todo: [], doing: [], done: [] },
          jobs: [],
          subjects: ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'],
          dashboardData: {
            totalHours: 0,
            completedTasks: 0,
            activeApplications: 0,
            sessionsThisWeek: 0
          }
        };
      }
      return res.json(fallbackData[userId]);
    }

    const userData = await db.collection('userData').findOne({ userId });
    if (!userData) {
      const defaultData = {
        userId,
        timerSessions: [],
        tasks: { todo: [], doing: [], done: [] },
        jobs: [],
        subjects: ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'],
        dashboardData: {
          totalHours: 0,
          completedTasks: 0,
          activeApplications: 0,
          sessionsThisWeek: 0
        }
      };
      res.json(defaultData);
    } else {
      res.json(userData);
    }
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Save timer session
app.post('/api/timer-sessions', authenticateToken, async (req, res) => {
  try {
    const { session } = req.body;
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (!fallbackData[userId]) {
        fallbackData[userId] = { 
          userId, 
          timerSessions: [], 
          tasks: { todo: [], doing: [], done: [] }, 
          jobs: [], 
          dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } 
        };
      }
      fallbackData[userId].timerSessions.push(session);
      return res.json({ success: true, fallback: true });
    }

    await db.collection('userData').updateOne(
      { userId },
      { 
        $push: { timerSessions: session },
        $setOnInsert: { userId }
      },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving timer session:', error);
    const userId = req.user.userId;
    if (!fallbackData[userId]) {
      fallbackData[userId] = { 
        userId, 
        timerSessions: [], 
        tasks: { todo: [], doing: [], done: [] }, 
        jobs: [], 
        dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } 
      };
    }
    fallbackData[userId].timerSessions.push(session);
    res.json({ success: true, fallback: true });
  }
});

// Update tasks
app.put('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { tasks } = req.body;
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (!fallbackData[userId]) {
        fallbackData[userId] = { 
          userId, 
          timerSessions: [], 
          tasks: { todo: [], doing: [], done: [] }, 
          jobs: [], 
          dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } 
        };
      }
      fallbackData[userId].tasks = tasks;
      return res.json({ success: true, fallback: true });
    }

    await db.collection('userData').updateOne(
      { userId },
      { 
        $set: { tasks },
        $setOnInsert: { userId }
      },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating tasks:', error);
    const userId = req.user.userId;
    if (!fallbackData[userId]) {
      fallbackData[userId] = { 
        userId, 
        timerSessions: [], 
        tasks: { todo: [], doing: [], done: [] }, 
        jobs: [], 
        dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } 
      };
    }
    fallbackData[userId].tasks = tasks;
    res.json({ success: true, fallback: true });
  }
});

// Save job application
app.post('/api/jobs', authenticateToken, async (req, res) => {
  try {
    const { job } = req.body;
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (!fallbackData[userId]) {
        fallbackData[userId] = { userId, timerSessions: [], tasks: { todo: [], doing: [], done: [] }, jobs: [], dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } };
      }
      fallbackData[userId].jobs.push(job);
      return res.json({ success: true, fallback: true });
    }

    await db.collection('userData').updateOne(
      { userId },
      { 
        $push: { jobs: job },
        $setOnInsert: { userId, timerSessions: [], tasks: { todo: [], doing: [], done: [] }, jobs: [], dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } }
      },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving job:', error);
    const userId = req.user.userId;
    if (!fallbackData[userId]) {
      fallbackData[userId] = { userId, timerSessions: [], tasks: { todo: [], doing: [], done: [] }, jobs: [], dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } };
    }
    fallbackData[userId].jobs.push(job);
    res.json({ success: true, fallback: true });
  }
});

// Update job application
app.put('/api/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const { updatedJob } = req.body;
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (fallbackData[userId] && fallbackData[userId].jobs) {
        const jobIndex = fallbackData[userId].jobs.findIndex(job => job.id === jobId);
        if (jobIndex !== -1) {
          fallbackData[userId].jobs[jobIndex] = updatedJob;
        }
      }
      return res.json({ success: true, fallback: true });
    }
    
    await db.collection('userData').updateOne(
      { userId, 'jobs.id': jobId },
      { $set: { 'jobs.$': updatedJob } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating job:', error);
    const userId = req.user.userId;
    if (fallbackData[userId] && fallbackData[userId].jobs) {
      const jobIndex = fallbackData[userId].jobs.findIndex(job => job.id === jobId);
      if (jobIndex !== -1) {
        fallbackData[userId].jobs[jobIndex] = updatedJob;
      }
    }
    res.json({ success: true, fallback: true });
  }
});

// Delete job application
app.delete('/api/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (fallbackData[userId] && fallbackData[userId].jobs) {
        fallbackData[userId].jobs = fallbackData[userId].jobs.filter(job => job.id !== jobId);
      }
      return res.json({ success: true, fallback: true });
    }
    
    await db.collection('userData').updateOne(
      { userId },
      { $pull: { jobs: { id: jobId } } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting job:', error);
    const userId = req.user.userId;
    if (fallbackData[userId] && fallbackData[userId].jobs) {
      fallbackData[userId].jobs = fallbackData[userId].jobs.filter(job => job.id !== jobId);
    }
    res.json({ success: true, fallback: true });
  }
});

// Update dashboard data
app.put('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const { dashboardData } = req.body;
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (!fallbackData[userId]) {
        fallbackData[userId] = { userId, timerSessions: [], tasks: { todo: [], doing: [], done: [] }, jobs: [], dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } };
      }
      fallbackData[userId].dashboardData = dashboardData;
      return res.json({ success: true, fallback: true });
    }
    
    await db.collection('userData').updateOne(
      { userId },
      { 
        $set: { dashboardData },
        $setOnInsert: { userId, timerSessions: [], tasks: { todo: [], doing: [], done: [] }, jobs: [], dashboardData }
      },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating dashboard data:', error);
    const userId = req.user.userId;
    if (!fallbackData[userId]) {
      fallbackData[userId] = { userId, timerSessions: [], tasks: { todo: [], doing: [], done: [] }, jobs: [], dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 } };
    }
    fallbackData[userId].dashboardData = dashboardData;
    res.json({ success: true, fallback: true });
  }
});

// Subject management endpoints

// Get subjects
app.get('/api/subjects', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (!fallbackData[userId]) {
        fallbackData[userId] = {
          userId,
          timerSessions: [],
          tasks: { todo: [], doing: [], done: [] },
          jobs: [],
          subjects: ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'],
          dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 }
        };
      }
      return res.json({ subjects: fallbackData[userId].subjects });
    }

    const userData = await db.collection('userData').findOne({ userId });
    if (!userData || !userData.subjects) {
      const defaultSubjects = ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'];
      return res.json({ subjects: defaultSubjects });
    }
    
    res.json({ subjects: userData.subjects });
  } catch (error) {
    console.error('Error fetching subjects:', error);
    res.status(500).json({ error: 'Failed to fetch subjects' });
  }
});

// Add subject
app.post('/api/subjects', authenticateToken, async (req, res) => {
  try {
    const { subject } = req.body;
    const userId = req.user.userId;
    
    if (!subject || typeof subject !== 'string' || subject.trim().length === 0) {
      return res.status(400).json({ error: 'Subject name is required' });
    }
    
    const trimmedSubject = subject.trim();
    
    if (!isConnected) {
      if (!fallbackData[userId]) {
        fallbackData[userId] = {
          userId,
          timerSessions: [],
          tasks: { todo: [], doing: [], done: [] },
          jobs: [],
          subjects: ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'],
          dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 }
        };
      }
      
      if (!fallbackData[userId].subjects.includes(trimmedSubject)) {
        fallbackData[userId].subjects.push(trimmedSubject);
      }
      return res.json({ success: true, subjects: fallbackData[userId].subjects });
    } else {
      // MongoDB operations - simplified approach
      const defaultSubjects = ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'];
      
      // Check if user document exists
      let userData = await db.collection('userData').findOne({ userId });
      
      if (!userData) {
        // Create new document with default subjects + new subject
        const newSubjects = [...defaultSubjects];
        if (!newSubjects.includes(trimmedSubject)) {
          newSubjects.push(trimmedSubject);
        }
        
        const newUserData = {
          userId,
          timerSessions: [],
          tasks: { todo: [], doing: [], done: [] },
          jobs: [],
          subjects: newSubjects,
          dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 }
        };
        
        await db.collection('userData').insertOne(newUserData);
        res.json({ success: true, subjects: newSubjects });
      } else {
        // Update existing document
        if (!userData.subjects || !Array.isArray(userData.subjects)) {
          userData.subjects = defaultSubjects;
        }
        
        // Add subject if not already present
        if (!userData.subjects.includes(trimmedSubject)) {
          await db.collection('userData').updateOne(
            { userId },
            { $addToSet: { subjects: trimmedSubject } }
          );
          userData.subjects.push(trimmedSubject);
        }
        
        res.json({ success: true, subjects: userData.subjects });
      }
    }
  } catch (error) {
    console.error('Error adding subject:', error);
    res.status(500).json({ error: 'Failed to add subject' });
  }
});

// Remove subject
app.delete('/api/subjects/:subject', authenticateToken, async (req, res) => {
  try {
    const { subject } = req.params;
    const userId = req.user.userId;
    
    if (!isConnected) {
      if (!fallbackData[userId]) {
        fallbackData[userId] = {
          userId,
          timerSessions: [],
          tasks: { todo: [], doing: [], done: [] },
          jobs: [],
          subjects: ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'],
          dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 }
        };
      }
      
      fallbackData[userId].subjects = fallbackData[userId].subjects.filter(s => s !== subject);
      return res.json({ success: true, subjects: fallbackData[userId].subjects });
    }

    await db.collection('userData').updateOne(
      { userId },
      { $pull: { subjects: subject } }
    );
    
    const userData = await db.collection('userData').findOne({ userId });
    res.json({ success: true, subjects: userData.subjects || [] });
  } catch (error) {
    console.error('Error removing subject:', error);
    res.status(500).json({ error: 'Failed to remove subject' });
  }
});

// Reset all data
app.delete('/api/reset', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const defaultData = {
      userId,
      timerSessions: [],
      tasks: { todo: [], doing: [], done: [] },
      jobs: [],
      subjects: ['Data Structures', 'Algorithms', 'System Design', 'Web Development', 'Database', 'Other'],
      dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 }
    };
    
    fallbackData[userId] = defaultData;
    
    if (isConnected) {
      await db.collection('userData').deleteOne({ userId });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error resetting data:', error);
    res.json({ success: true, fallback: true });
  }
});

// Catch all handler for React Router (must be after API routes)
if (process.env.NODE_ENV === 'production') {
  app.use((req, res) => {
    // Only serve index.html for GET requests that don't start with /api
    if (req.method === 'GET' && !req.path.startsWith('/api')) {
      res.sendFile(path.join(__dirname, 'dist/index.html'));
    } else {
      res.status(404).json({ error: 'Not found' });
    }
  });
}

// Start server
connectToDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  });
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`Received ${signal}. Shutting down server gracefully...`);
  if (client) {
    console.log('Closing MongoDB connection...');
    await client.close();
  }
  process.exit(0);
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
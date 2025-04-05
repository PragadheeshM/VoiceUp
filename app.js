const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const usermodel = require('./model/user');
const postmodel = require("./model/post")
const { Municipality, Police, Electricity, RTO } = require('./model/departments');
const { categorizeComplaint, getGovernmentSchemeInfo } = require('./utils/categorizer');
const cookieParser = require('cookie-parser');
const { verify } = require('crypto');
const mongoose = require('mongoose');
const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

// Validate environment variables
if (!process.env.GEMINI_API_KEY) {
  console.error('Error: GEMINI_API_KEY is not set in .env file');
  process.exit(1);
}

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Define Complaint model schema if it doesn't exist yet
const complaintSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER']
  },
  location: {
    type: String,
    required: true
  },
  priority: {
    type: String,
    required: true,
    enum: ['low', 'medium', 'high'],
    default: 'low'
  },
  status: {
    type: String,
    default: 'PENDING',
    enum: ['PENDING', 'PROCESSING', 'RESOLVED', 'REJECTED']
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  attachments: [String],
  comments: [{
    text: String,
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    role: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
});

// Create model if it doesn't exist yet
let Complaint;
try {
  Complaint = mongoose.model('Complaint');
} catch (error) {
  Complaint = mongoose.model('Complaint', complaintSchema);
}

// MongoDB Connection with enhanced error handling
console.log('Attempting to connect to MongoDB...');
mongoose.connect('mongodb://127.0.0.1:27017/Data-Association', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 10000,
  retryWrites: true,
  retryReads: true,
  maxPoolSize: 10,
  minPoolSize: 5
})
  .then(() => {
    console.log('Connected to MongoDB successfully');

    // Create default admin account if it doesn't exist
    createDefaultAdmin();
  })
  .catch((err) => {
    console.error('MongoDB connection error details:', {
      name: err.name,
      message: err.message,
      code: err.code,
      codeName: err.codeName
    });
    // Don't exit immediately, try to reconnect
    console.log('Attempting to reconnect...');
    setTimeout(() => {
      mongoose.connect('mongodb://localhost:27017/Data-Association', {
        useNewUrlParser: true,
        useUnifiedTopology: true
      }).catch(console.error);
    }, 5000);
  });

// Function to create default admin account
async function createDefaultAdmin() {
  try {
    // Check if admin already exists
    const adminExists = await usermodel.findOne({ role: 'ADMIN' });

    if (!adminExists) {
      // Create default admin account
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash('admin123', salt);

      await usermodel.create({
        username: 'admin',
        name: 'Administrator',
        age: 30,
        email: 'admin@example.com',
        password: hash,
        role: 'ADMIN'
      });

      console.log('Default admin account created successfully');
      console.log('Email: admin@example.com');
      console.log('Password: admin123');
    } else {
      console.log('Admin account already exists');
    }
  } catch (error) {
    console.error('Error creating default admin account:', error);
  }
}

// Add connection event listeners
mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected from MongoDB');
});

app.set('view engine', 'ejs');
app.set('layout', 'layout');
app.use(expressLayouts);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "public")));

// Add middleware to make user authentication state available to all pages
app.use(async (req, res, next) => {
  res.locals.user = null;
  const token = req.cookies.Token;

  if (token) {
    try {
      const decoded = jwt.verify(token, "shhh");
      const user = await usermodel.findById(decoded.userId);
      if (user) {
        res.locals.user = user;
      }
    } catch (error) {
      console.error('Token verification error:', error);
      // Clear invalid token
      res.clearCookie('Token');
    }
  }
  next();
});

app.get('/', (req, res) => {
  res.render('home', { title: 'Home' });
}
)
app.get('/create', (req, res) => {
  res.render('create', { title: 'Register' });
}
)

app.get("/profile", isLoggedIn, async (req, res) => {
  // If username is not in the token, fetch it from the database
  if (!req.user.username) {
    const userFromDb = await usermodel.findById(req.user.userId);
    if (userFromDb) {
      req.user.username = userFromDb.username;
    } else {
      // If user not found in database, redirect to home
      return res.redirect('/');
    }
  }

  // Redirect to the username-based profile URL
  res.redirect(`/profile/${req.user.username}`);
})

// New username-based profile route
app.get("/profile/:username", isLoggedIn, async (req, res) => {
  try {
    let displaydata = await usermodel.find();
    let user = await usermodel.findOne({ username: req.params.username }).populate("posts");

    // If user not found, redirect to the logged-in user's profile
    if (!user) {
      // If username is not in the token, fetch it from the database
      if (!req.user.username) {
        const userFromDb = await usermodel.findById(req.user.userId);
        if (userFromDb) {
          req.user.username = userFromDb.username;
        } else {
          // If user not found in database, redirect to home
          return res.redirect('/');
        }
      }
      return res.redirect(`/profile/${req.user.username}`);
    }

    // Get the logged-in user's full information
    const loggedInUser = await usermodel.findById(req.user.userId);

    let blogg = await postmodel.find();
    res.render('profile', {
      title: 'Profile',
      user,
      blogg,
      displaydata,
      loggedInUser,
      isOwnProfile: loggedInUser._id.toString() === user._id.toString(),
      isAdmin: loggedInUser.role === 'ADMIN'
    });
  } catch (error) {
    console.error('Error loading profile:', error);
    res.redirect('/');
  }
});

app.get('/logout', async (req, res) => {
  res.clearCookie('Token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.redirect('/');
});


app.post("/post", isLoggedIn, async (req, res) => {
  let user = await usermodel.findOne({ email: req.user.email });
  let { content } = req.body;
  let post = await postmodel.create({
    userinfo: user._id,
    content
  })

  user.posts.push(post._id)
  await user.save();
  res.redirect('/profile');
}
)
app.post('/create', async (req, res) => {
  let { username, email, age, password } = req.body;

  let user = await usermodel.findOne({ email });
  if (user) {
    res.send('<span>You must be logged in first .. <a href="/">Log In</a></span>');
  }
  else {
    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(password, salt, async (err, hash) => {
        // All users created through this form will be CITIZEN
        const userRole = 'CITIZEN';

        const newuserdata = await usermodel.create({
          username,
          name: username,
          age,
          email,
          password: hash,
          role: userRole
        })
        let token = jwt.sign({ email: email, role: userRole }, "shhh");
        res.cookie("Token", token);
        res.redirect('/profile');
      })
    })
  }
})
app.post('/login', async (req, res) => {
  let { email, password, remember } = req.body;
  let user = await usermodel.findOne({ email });
  if (user) {
    let verify = bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        // Set token expiration based on "Remember Me" checkbox
        const expiresIn = remember ? '30d' : '1d';
        let token = jwt.sign({
          email: email,
          role: user.role,
          userId: user._id,
          username: user.username
        }, "shhh", { expiresIn });

        // Set cookie with secure options
        res.cookie("Token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
          sameSite: 'strict',
          maxAge: remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000 // 30 days or 1 day
        });

        res.redirect('/profile');
      }
      else {
        res.send("Incorrect Credentials. Verify your email and password");
      }
    });
  }
  else {
    res.send('<span>No such User Exists Create one ? .. <a href="/">Create</a></span>');
  }
})

function isLoggedIn(req, res, next) {
  if (!req.cookies.Token || req.cookies.Token === "") {
    // For API responses
    if (req.xhr || req.path.includes('/api/')) {
      return res.status(401).json({ error: 'You must be logged in to access this resource' });
    }

    // Check if the request is for complaints page specifically
    if (req.path === '/complaints') {
      return res.render('login', {
        title: 'Login',
        error: 'Please login first to register a complaint'
      });
    }

    // Generic message for other protected routes
    return res.render('login', {
      title: 'Login',
      error: 'You must be logged in to access this resource'
    });
  }

  try {
    let data = jwt.verify(req.cookies.Token, "shhh");
    console.log('JWT token verified, user data:', data);
    
    // Make sure the user object has all required fields
    if (!data.userId) {
      console.error('JWT token missing userId:', data);
      res.clearCookie('Token');
      return res.render('login', {
        title: 'Login',
        error: 'Your session is invalid. Please login again.'
      });
    }
    
    // Set the user data in the request object
    req.user = {
      userId: data.userId,
      email: data.email,
      role: data.role,
      username: data.username
    };
    
    next();
  } catch (error) {
    // JWT verification failed
    console.error('JWT verification error:', error);
    res.clearCookie('Token');
    return res.render('login', {
      title: 'Login',
      error: 'Your session has expired. Please login again.'
    });
  }
}

// Role-based middleware functions
function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'ADMIN') {
    next();
  } else {
    res.send('<span>Access denied. Admin privileges required. <a href="/">Go Back</a></span>');
  }
}

function isOfficer(req, res, next) {
  if (req.user && (req.user.role === 'ADMIN' || req.user.role === 'OFFICER')) {
    next();
  } else {
    res.send('<span>Access denied. Officer privileges required. <a href="/">Go Back</a></span>');
  }
}

function isCitizen(req, res, next) {
  if (req.user && (req.user.role === 'ADMIN' || req.user.role === 'OFFICER' || req.user.role === 'CITIZEN')) {
    next();
  } else {
    res.send('<span>Access denied. Citizen privileges required. <a href="/">Go Back</a></span>');
  }
}

app.get('/home', (req, res) => {
  res.render('home', { title: 'Home' });
}
)

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' });
}
)

app.get('/currentStatus', (req, res) => {
  // Pass an empty applications array for now
  res.render('currentStatus', { title: 'Application Status', applications: [] });
});

// Complaints routes
app.get('/complaints', isLoggedIn, (req, res) => {
  res.render('file-complaint', {
    title: 'File a Complaint', categories: [
      'INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION',
      'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER'
    ]
  });
});

app.post('/complaints', isLoggedIn, async (req, res) => {
  try {
    const { title, description, location } = req.body;
    
    // Make sure we have a valid user ID
    if (!req.user.userId) {
      console.error('User object missing userId:', req.user);
      return res.render('file-complaint', {
        title: 'File a Complaint',
        error: 'Authentication error. Please try logging in again.',
        categories: ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER']
      });
    }

    if (!description) {
      return res.render('file-complaint', {
        title: 'File a Complaint',
        error: 'Description is required for AI categorization',
        categories: ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER']
      });
    }

    // Use AI to categorize the complaint
    const category = await categorizeComplaint(description);
    
    // Get relevant government scheme information
    const schemeInfo = await getGovernmentSchemeInfo(category, description);

    // Create complaint using the main Complaint model
    const complaint = new Complaint({
      title,
      description,
      location,
      userId: req.user.userId,
      category,
      status: 'PENDING',
      priority: 'medium'
    });

    await complaint.save();

    // Redirect with success message and scheme information
    res.render('file-complaint', {
      title: 'File a Complaint',
      success: 'Complaint submitted successfully and categorized by AI',
      categories: ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER'],
      schemeInfo: schemeInfo
    });
  } catch (error) {
    console.error('Error submitting complaint:', error);
    res.render('file-complaint', {
      title: 'File a Complaint',
      error: 'Failed to submit complaint. Please try again. Error: ' + error.message,
      categories: ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER']
    });
  }
});

app.get('/my-complaints', isLoggedIn, async (req, res) => {
  try {
    // Fetch complaints for the current user using the correct user ID field
    const complaints = await Complaint.find({ userId: req.user.userId }).sort({ createdAt: -1 });

    res.render('my-complaints', {
      title: 'My Complaints',
      complaints
    });
  } catch (error) {
    console.error('Error fetching complaints:', error);
    res.status(500).render('my-complaints', {
      title: 'My Complaints',
      error: 'Error loading complaints. Please try again later.'
    });
  }
});

app.get('/complaint/:id', isLoggedIn, async (req, res) => {
  try {
    const complaint = await Complaint.findById(req.params.id);

    if (!complaint) {
      return res.status(404).send('Complaint not found');
    }

    // Check if user owns this complaint or is admin/officer
    if (complaint.userId.toString() !== req.user.userId &&
      req.user.role !== 'ADMIN' && req.user.role !== 'OFFICER') {
      return res.status(403).send('Access denied');
    }

    res.render('complaint-details', { title: 'Complaint Details', complaint });
  } catch (error) {
    console.error('Error fetching complaint details:', error);
    res.status(500).send('Error loading complaint details');
  }
});

// Admin dashboard for complaints
app.get('/admin-complaints', isLoggedIn, isOfficer, async (req, res) => {
  try {
    // Fetch all complaints using the main Complaint model
    const complaints = await Complaint.find().sort({ createdAt: -1 });

    res.render('admin-complaints', {
      title: 'Manage Complaints',
      complaints
    });
  } catch (error) {
    console.error('Error fetching complaints for admin:', error);
    res.status(500).render('admin-complaints', {
      title: 'Manage Complaints',
      error: 'Error loading complaints. Please try again later.'
    });
  }
});

app.post('/update-complaint-status', isLoggedIn, isOfficer, async (req, res) => {
  try {
    const { complaintId, status, comment } = req.body;

    const complaint = await Complaint.findById(complaintId);
    if (!complaint) {
      return res.status(404).send('Complaint not found');
    }

    // Update status
    complaint.status = status;
    complaint.updatedAt = Date.now();

    // Add comment if provided
    if (comment) {
      complaint.comments.push({
        text: comment,
        userId: req.user.userId,
        role: req.user.role
      });
    }

    await complaint.save();
    res.redirect('/admin-complaints');
  } catch (error) {
    console.error('Error updating complaint status:', error);
    res.status(500).send('Error updating complaint');
  }
});

// Admin dashboard route
app.get('/admin', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const officers = await usermodel.find({ role: 'OFFICER' });
    const citizens = await usermodel.find({ role: 'CITIZEN' });

    // Fetch all complaints using the main Complaint model
    const complaints = await Complaint.find().sort({ createdAt: -1 });

    res.render('admin-dashboard', {
      title: 'Admin Dashboard',
      officers,
      citizens,
      complaints
    });
  } catch (error) {
    console.error('Error fetching admin dashboard data:', error);
    res.status(500).render('admin-dashboard', {
      title: 'Admin Dashboard',
      error: 'Error loading dashboard data. Please try again later.'
    });
  }
});

// Create officer route
app.get('/create-officer', isLoggedIn, isAdmin, (req, res) => {
  res.render('create-officer', { title: 'Create Officer' });
});

app.post('/create-officer', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const { username, email, age, password } = req.body;

    // Check if user already exists
    const existingUser = await usermodel.findOne({ email });
    if (existingUser) {
      return res.render('create-officer', {
        title: 'Create Officer',
        error: 'Email already registered'
      });
    }

    // Create new officer account
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    await usermodel.create({
      username,
      name: username,
      age,
      email,
      password: hash,
      role: 'OFFICER'
    });

    res.redirect('/admin');
  } catch (error) {
    console.error('Error creating officer:', error);
    res.render('create-officer', {
      title: 'Create Officer',
      error: 'Error creating officer account'
    });
  }
});

// Delete user route
app.post('/delete-user/:userId', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;

    // Prevent deleting the last admin
    const userToDelete = await usermodel.findById(userId);
    if (!userToDelete) {
      return res.status(404).send('User not found');
    }

    if (userToDelete.role === 'ADMIN') {
      const adminCount = await usermodel.countDocuments({ role: 'ADMIN' });
      if (adminCount <= 1) {
        return res.status(400).send('Cannot delete the last admin account');
      }
    }

    await usermodel.findByIdAndDelete(userId);
    res.redirect('/admin');
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).send('Error deleting user');
  }
});

// Track application status route
app.post('/track-status', async (req, res) => {
  try {
    const { applicationId, email } = req.body;

    // In a real application, you would query your database for the application
    // For now, we'll use sample data
    const sampleApplications = [
      {
        id: 'APP001',
        status: 'PENDING',
        submittedDate: new Date(Date.now() - 86400000), // 1 day ago
        lastUpdated: new Date(Date.now() - 43200000), // 12 hours ago
        type: 'Document Verification',
        description: 'Passport renewal application'
      },
      {
        id: 'APP002',
        status: 'PROCESSING',
        submittedDate: new Date(Date.now() - 172800000), // 2 days ago
        lastUpdated: new Date(Date.now() - 86400000), // 1 day ago
        type: 'License Renewal',
        description: 'Driver\'s license renewal'
      },
      {
        id: 'APP003',
        status: 'RESOLVED',
        submittedDate: new Date(Date.now() - 259200000), // 3 days ago
        lastUpdated: new Date(Date.now() - 172800000), // 2 days ago
        type: 'Tax Services',
        description: 'Income tax filing'
      }
    ];

    // Find the application with the matching ID and email
    // In a real application, you would verify the email matches the application
    const application = sampleApplications.find(app => app.id === applicationId);

    if (application) {
      // Render the application status page with the found application
      res.render('application-status', {
        title: 'Application Status',
        application,
        email
      });
    } else {
      // If no application is found, redirect back to home with an error message
      res.render('home', {
        title: 'Home',
        error: 'No application found with the provided ID and email. Please check your details and try again.'
      });
    }
  } catch (error) {
    console.error('Error tracking application status:', error);
    res.render('home', {
      title: 'Home',
      error: 'An error occurred while tracking your application. Please try again later.'
    });
  }
});

// Chat API endpoint
app.post('/api/chat', async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    // Get the Gemini model with flash-1.5 configuration
    const model = genAI.getGenerativeModel({
      model: "gemini-1.5-flash",
      generationConfig: {
        temperature: 0.7,
        topK: 40,
        topP: 0.95,
        maxOutputTokens: 1024,
      }
    });

    // Create a system prompt for the government grievance assistant
    const systemPrompt = `You are a government grievance assistant chatbot designed to help Indian citizens understand and use the government grievance redressal system. You specialize in helping users:

1. Identify the correct department for their complaint.
2. Understand the grievance filing process on official platforms like CPGRAMS (Centralized Public Grievance Redress And Monitoring System).
3. Find relevant government schemes that may assist them.
4. Answer questions related to ministry responsibilities, complaint tracking, timelines, and escalation procedures.

When helping users:
- Be polite, professional, and empathetic
- Provide accurate information about government departments and schemes
- Explain processes in simple, step-by-step terms
- Suggest relevant government schemes when appropriate
- Guide users on how to track their complaints
- Explain escalation procedures when needed

If a user is asking about filing a complaint, guide them to use the complaint filing system on this portal.`;

    // Generate response with the system prompt
    const result = await model.generateContent([
      { role: "system", content: systemPrompt },
      { role: "user", content: message }
    ]);
    
    const response = await result.response;
    const text = response.text();

    res.json({ response: text });
  } catch (error) {
    console.error('Error in chat API:', error);
    res.status(500).json({
      error: 'An error occurred while processing your request',
      details: error.message
    });
  }
});

// Route to get government scheme information by category
app.get('/api/schemes/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const { description } = req.query;
    
    // Validate category
    const validCategories = ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({ error: 'Invalid category' });
    }
    
    // Get scheme information
    const schemeInfo = await getGovernmentSchemeInfo(category, description || '');
    
    res.json(schemeInfo);
  } catch (error) {
    console.error('Error getting scheme information:', error);
    res.status(500).json({
      error: 'An error occurred while fetching scheme information',
      details: error.message
    });
  }
});

app.listen(3000);
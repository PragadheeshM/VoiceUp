const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const usermodel = require('./model/user');
const postmodel = require("./model/post")
const cookieParser = require('cookie-parser');
const { verify } = require('crypto');
const mongoose = require('mongoose');

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
  let displaydata = await usermodel.find()
  let user = await usermodel.findOne({ email: req.user.email }).populate("posts")
  let blogg = await postmodel.find();
  res.render('profile', { title: 'Profile', user, blogg, displaydata });
}
)
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
          userId: user._id
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
  if (req.cookies.Token === "") {
    res.send('<span>You must be logged in first .. <a href="/">Log In</a></span>');
  }
  else {
    let data = jwt.verify(req.cookies.Token, "shhh")
    req.user = data;
    next();
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

app.get('/services', (req, res) => {
  res.render('services', { title: 'Services' });
});

// Admin dashboard route
app.get('/admin', isLoggedIn, isAdmin, async (req, res) => {
    try {
        const officers = await usermodel.find({ role: 'OFFICER' });
        const citizens = await usermodel.find({ role: 'CITIZEN' });
        
        // Sample complaints data (replace with actual data from your database)
        const complaints = [
            {
                _id: '1',
                title: 'Road Repair Request',
                status: 'PENDING',
                createdAt: new Date()
            },
            {
                _id: '2',
                title: 'Water Supply Issue',
                status: 'PROCESSING',
                createdAt: new Date(Date.now() - 86400000) // 1 day ago
            },
            {
                _id: '3',
                title: 'Garbage Collection',
                status: 'RESOLVED',
                createdAt: new Date(Date.now() - 172800000) // 2 days ago
            },
            {
                _id: '4',
                title: 'Street Light Repair',
                status: 'REJECTED',
                createdAt: new Date(Date.now() - 259200000) // 3 days ago
            }
        ];
        
        res.render('admin-dashboard', { 
            title: 'Admin Dashboard',
            officers,
            citizens,
            complaints
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error loading admin dashboard');
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
app.post('/delete-user', isLoggedIn, isAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        
        // Prevent deleting the last admin
        const userToDelete = await usermodel.findById(userId);
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

app.listen(3000);
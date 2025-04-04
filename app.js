const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const usermodel = require('./model/user');
const postmodel =require("./model/post")
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
    const token = req.cookies.token;
    
    if (token) {
        try {
            const decoded = jwt.verify(token, 'your-secret-key');
            const user = await usermodel.findById(decoded.userId);
            if (user) {
                res.locals.user = user;
            }
        } catch (error) {
            console.error('Token verification error:', error);
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

app.get("/profile",isLoggedIn,async (req,res) => {
  let displaydata=await usermodel.find()
  let user=await usermodel.findOne({email:req.user.email}).populate("posts")
  let blogg = await postmodel.find();
  res.render('profile',{title: 'Profile', user,blogg,displaydata});
}
) 
app.get('/logout', async (req, res) => {
  res.cookie("Token", "");
  res.redirect('/');
}
)


app.post("/post",isLoggedIn,async(req,res) => {
  let user=await usermodel.findOne({email:req.user.email});
  let {content}=req.body;
  let post=await postmodel.create({
    userinfo:user._id,
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
  let { email, password } = req.body;
  let user = await usermodel.findOne({ email });
  if (user) {
    let verify = bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        let token = jwt.sign({ email: email, role: user.role }, "shhh");
        res.cookie("Token", token);
        res.redirect('/profile')
      }
      else {
        res.send("Incorrect Credintials. Verify your email and password")
      }
    });
  }
  else {
    res.send('<span>No such User Exists Create one ? .. <a href="/">Create</a></span>')
  }
})

function isLoggedIn(req,res,next){
  if(req.cookies.Token===""){
    res.send('<span>You must be logged in first .. <a href="/">Log In</a></span>'); 
  }
  else{
    let data=jwt.verify(req.cookies.Token, "shhh")
    req.user=data;
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

// Route to create officer account (admin only)
app.get('/create-officer', isLoggedIn, isAdmin, (req, res) => {
  res.render('create-officer', { title: 'Create Officer' });
});

app.post('/create-officer', isLoggedIn, isAdmin, async (req, res) => {
  let { username, email, age, password } = req.body;

  let user = await usermodel.findOne({ email });
  if (user) {
    res.send('<span>Email already registered. <a href="/create-officer">Try Again</a></span>');
  } else {
    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(password, salt, async (err, hash) => {
        const newOfficer = await usermodel.create({
          username,
          name: username,
          age,
          email,
          password: hash,
          role: 'OFFICER'
        });
        res.send('<span>Officer account created successfully. <a href="/admin-dashboard">Go to Dashboard</a></span>');
      });
    });
  }
});

// Admin dashboard route
app.get('/admin-dashboard', isLoggedIn, isAdmin, async (req, res) => {
  const officers = await usermodel.find({ role: 'OFFICER' });
  const citizens = await usermodel.find({ role: 'CITIZEN' });
  res.render('admin-dashboard', { title: 'Admin Dashboard', officers, citizens });
});

app.listen(3000);
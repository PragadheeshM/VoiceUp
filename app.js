const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const usermodel = require('./model/user');
const postmodel =require("./model/post")
const cookieParser = require('cookie-parser');
const { verify } = require('crypto');

app.set("view engine", "ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "public")));

app.get('/', (req, res) => {
  res.render('index');
}
)
app.get('/create', (req, res) => {
  res.render('create');
}
)

app.get("/profile",isLoggedIn,async (req,res) => {
  let displaydata=await usermodel.find()
  let user=await usermodel.findOne({email:req.user.email}).populate("posts")
  let blogg = await postmodel.find();
  res.render('profile',{user,blogg,displaydata});
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
    // res.send('<span>No such User Exists Create one ? .. <a href="/">Create</a></span>')
    res.send('<span>You must be logged in first .. <a href="/">Log In</a></span>');
    // res.redirect('/')
    // res.send('<span>This Email Is already registered Log In Instead ? .. <a href="/">Log In</a>')
  }
  else{

    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(password, salt, async (err, hash) => {
        const newuserdata = await usermodel.create({
          username,
          name: username,
          age,
          email,
          password: hash
        })
        let token = jwt.sign({ email: email }, "shhh");
        res.cookie("Token", token);
        res.redirect('/profile');
      }
      )
    }
    ) 
  }
 

}
)
app.post('/login', async (req, res) => {
  let { email, password } = req.body;
  let user = await usermodel.findOne({ email });
  if (user) {
    let verify = bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        let token = jwt.sign({ email: email }, "shhh");
        res.cookie("Token", token);
        res.redirect('/profile')
      }
      else{
        res.send("Incorrect Credintials. Verify your email and password")
      }

    }
    );
  }
  else{
    res.send('<span>No such User Exists Create one ? .. <a href="/">Create</a></span>')
  }
}
)

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

app.get('/home', (req, res) => {
  res.render('home');
}
)

app.get('/login', (req, res) => {
  res.render('login');
}
)

app.get('/currentStatus', (req, res) => {
  res.render('currentStatus');
});

app.get('/services', (req, res) => {
  res.render('services');
});
 
app.listen(3000);
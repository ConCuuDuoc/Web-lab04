const express = require("express")
const app = express()
//hash
const bcrypt = require("bcrypt") 
//passport authen
const passport = require("passport")
const initializePassport = require("./middleware/passport-config")
const flash = require("express-flash")
const methodOverride = require("method-override")
//model
const { InitiateMongoServer, mongoose } = require("./model/db");
const User = require("./model/user");
//session
const cookieParser = require('cookie-parser');
const session = require("express-session");
//session storage
const MongoStore = require('connect-mongo');

if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

InitiateMongoServer();

initializePassport(
  passport,
  async (email) => await User.findOne({ email }),
  async (id) => await User.findById(id)
);
//serve static files
app.use(express.static('views'));

app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.urlencoded({extended: false}))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false, 
    saveUninitialized: false,
    store: MongoStore.create(mongoose.connection),
    cookie: {
      maxAge: 30 * 60 * 1000,
    },
  })
)
app.use(passport.initialize()) 
app.use(passport.session())
app.use(methodOverride("_method"))


// Pót login
app.post("/login", checkNotAuthenticated, passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
}))

// Pótt res
app.post("/register", checkNotAuthenticated, async (req, res) => {
  try {
      const { name, email, password, confirmPassword, phone } = req.body;

      if (password !== confirmPassword) {
          return res.status(400).send("Passwords do not match");
      }
      if (!password || password.trim() === "") {
          return res.status(400).send("Password cannot be empty");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({
          name,
          email,
          password: hashedPassword,
          phone,
      });
      await user.save();
      console.log(user);
      res.redirect("/login");
  } catch (e) {
      console.error(e);
      res.redirect("/register");
  }
});



// Routes
app.get('/', checkAuthenticated, (req, res) => {
    res.render("index.ejs", {name: req.user.name})
})

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render("login.ejs")
})

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render("register.ejs")
})

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/");
  }
);

// End Routes

app.delete("/logout", (req, res) => {
    req.logout(req.user, err => {
        if (err) return next(err)
        res.redirect("/")
    })
})


async function checkAuthenticated(req, res, next) {
  //req.session.passport.user !== undefined  
  if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/login");
  }
  
function checkNotAuthenticated(req, res, next){
  //req.session.passport.user !== undefined  
  if(req.isAuthenticated()){
        return res.redirect("/")
    }
    next()
}

app.listen(5500);
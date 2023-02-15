//jshint esversion:6

const bodyParser = require('body-parser');
const ejs = require("ejs");
const express = require('express');
const mongoose = require('mongoose');
mongoose.set('strictQuery', false);
const session = require('express-session'); // Create a session middleware with the given options. Session data is not saved in the cookie itself, just the session ID. Session data is stored server-side.
const passport = require('passport'); // Passport is Express-compatible authentication middleware for Node.js. Passport's sole purpose is to authenticate requests, which it does through an extensible set of plugins known as strategies.
const passportLocalMongoose = require('passport-local-mongoose'); // Passport-Local Mongoose is a Mongoose plugin that simplifies building username and password login with Passport.
require('dotenv').config() // Level 2 Encryption (B): Using ENV variables for encryption keys/secrets 
const secret = process.env.SECRET_KEY;

/**  Setting up the app **/
const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

/* Level 5 Authentication - Cookies: Authentication with Passport package */
// Setting up/Configuring the session
app.use(session({
  secret: secret,   // A long string, that we will save in our .env file. This is the secret used to sign the session ID cookie. This can be either a string for a single secret, or an array of multiple secrets. 
  resave: false,            // Forces the session to be saved back to the session store, even if the session was never modified during the request.
  saveUninitialized: true,  // Forces a session that is "uninitialized" to be saved to the store. A session is uninitialized when it is new but not modified. 
  cookie: { secure: false }  // Settings object for the session ID cookie. The default value is { path: '/', httpOnly: true, secure: false, maxAge: null }.
}));
// Initalizating the passport package to use it for Authentication */
app.use(passport.initialize());
// Making passport deal with our login sessions */
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/secretsDB');

/* Schemas & Models */
const secretSchema = new mongoose.Schema({
    secret: {type:String, required:[true, "A secret is no secret without the secret..."]}
});
const Secret = new mongoose.model("Secret", secretSchema);
// Creating the Schema
const userSchema = new mongoose.Schema({
    username: {type:String},
    password: {type:String}
});
// Adding the passport-local-mongoose package as plugin to our Schema, in order to make it hash&salt our passwords
userSchema.plugin(passportLocalMongoose);
// Initalizing the Model from the Schema
const User = new mongoose.model("User", userSchema);

/* Passport local configurations */
// Creating the authentication strategy based on the 'User' Model (username, password)
passport.use(User.createStrategy());
// use static serialize and deserialize of Model for passport Session support
passport.serializeUser(User.serializeUser());       // cookie is created and saved (stuffed) with the authentication data (User.username, User.password)
passport.deserializeUser(User.deserializeUser());   // cookie is read (crumbled), message inside is discovered for authentication


/* URL Routes */
app.get("/", function(req, res){
    res.render("home");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/submit", function(req, res){
    res.render("submit");
});

app.get("/secrets", function(req, res){
    if (req.isAuthenticated()){ // checking if the user is authenticated by passport.authenticate (relying here on session, passport, passport-local, passport-local-mongoose)
        Secret.find({}, function(err, foundSecrets){
            if (err){
                res.send(err);
            }
            else {
                res.render("secrets", {"Secrets":foundSecrets});;
            }
        });
    }
    else {
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    req.logout(function(err){
        if (err){
            res.send(err);
        }
        else {
            res.redirect("/");
        }
    });
})

app.post("/register", function(req, res){
    // Level 1 Encryption: User-password registration
    
    // the register method comes from the passport-local-mongoose package and is syntactic sugar for new User creation and save
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) { 
            console.log(err);
            res.redirect("/register");
        }
        else {
             // authenticate user --> user will be able to directly go to 'secrets' while they are logged in
            passport.authenticate('local')(req, res, function () {
                res.redirect('/secrets');
            });
        }
    })
});

app.post("/login", function(req, res){
        const user = new User({username: req.body.username, password: req.body.password});
        req.login(user, function(err){
            if (err) {
                res.send(err);
            }
            else {
                // authenticate user --> user will be able to directly go to 'secrets' while they are logged in
                passport.authenticate('local')(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        })
    }
);

app.post("/submit", function(req, res){
    const secret = new Secret({secret: req.body.secret});
    secret.save();
    res.redirect("/secrets");
});

app.listen(3000, function(){
    console.log("Listening on port 3000");
})
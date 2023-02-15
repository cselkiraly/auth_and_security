//jshint esversion:6

const bodyParser = require('body-parser');
const ejs = require("ejs");
const express = require('express');
const mongoose = require('mongoose');
mongoose.set('strictQuery', false);
/* const encrypt = require('mongoose-encryption');
const md5 = require('md5'); // Level 3 Encryption: Hashing our password */
const bcrypt = require('bcrypt'); // Level 4 Encryption: Hashing & Salting our password
const saltRounds = 10;

// dotenv will make keys defined in the root .env file available using process.env
require('dotenv').config() // Level 2 Encryption (B): Using ENV variables for encryption keys/secrets

/* Setting up the app */
const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect('mongodb://localhost:27017/secretsDB');

/* Schemas & Models */
userSchema = new mongoose.Schema({
    email: {type:String, required:[true, "Email is required"]},
    password: {type:String, required:[true, "Password is required"]}
});
// Level 2 Encryption (A) - Adding the encryption to the Schema -> psw will be encrypted in Database
/* const secret = "Thisisourlittlesecret"; */
const secret = process.env.SECRET_KEY;
/* Typing the secret into the app.js is not a good idea.
Our app.js is easily accesable and the hacker can use the same mongoose-encryption module to decrypt with our known secret. */
User = mongoose.model("User", userSchema);
secretSchema = new mongoose.Schema({
    secret: {type:String, required:[true, "A secret is no secret without the secret..."]}
});
Secret = new mongoose.model("Secret", secretSchema);

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
    Secret.find({}, function(err, foundSecrets){
        if (err){
            res.send("Error during searching for secrets");
        }
        else {
            console.log(foundSecrets);
            const Secrets = foundSecrets;
            res.render("secrets", {Secrets:Secrets});
        }
    });
});

app.get("/logout", function(req, res){
    res.redirect("/login");
})

app.post("/register", function(req, res){
    // Level 1 Encryption: User-password registration
    bcrypt.hash(req.body.password, saltRounds, function(err, hash){
        if (err){
            res.send(err);
        }
        else {
            const newUser = User({email: req.body.username, password: hash})
            newUser.save(function(err){
                if (err){
                    res.send(err);
                }
                else {
                    res.redirect('/secrets');
                }
            });
        }
    })

    
});

app.post("/login", function(req, res){
    User.findOne({email: req.body.username},function(err, foundUser){
        if (err){
            res.send(err);
        }
        // Password check
        else if (foundUser) {
            bcrypt.compare(req.body.password, foundUser.password, function(err,result){
                if (err) {
                    res.send(err);
                }
                else if (result === true){
                    res.redirect("/secrets");
                }
                else {
                    console.log("Wrong password for user: " + foundUser.username);
                    res.redirect("/login");
                }
            });
        }
        else {
            console.log("No user with given email.");
            res.redirect("/login");
        }
    });
      
});

app.post("/submit", function(req, res){
    const secret = new Secret({secret: req.body.secret});
    secret.save();
    res.redirect("/secrets");
});

app.listen(3000, function(){
    console.log("Listening on port 3000");
})
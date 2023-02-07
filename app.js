//jshint esversion:6

const bodyParser = require('body-parser');
const ejs = require("ejs");
const express = require('express');
const mongoose = require('mongoose');
mongoose.set('strictQuery', false);
// The mongoose-enryption encrypts when we use ModelInstance.save() and decrypts upon Model.find()
const encrypt = require('mongoose-encryption');
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
userSchema.plugin(encrypt, {secret: secret, encryptedFields: ['password']}); 
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
    const newUser = User({email: req.body.username, password: req.body.password})
    newUser.save(function(err){
        if (err){
            res.send(err);
        }
        else {
            res.redirect('/secrets');
        }
    });
});

app.post("/login", function(req, res){
    User.findOne({email: req.body.username},function(err, foundUser){
        if (err){
            res.send(err);
        }
        // Password check
        else if (foundUser.password === req.body.password) {
            res.redirect("/secrets");
        }
        else {
            console.log("No user with given email-password combination.")
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
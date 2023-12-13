const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    googleId: String,
    name: String,
    email: { type: String, unique: true },
    password: String,
    phone: String,
});

const User = mongoose.model("User", userSchema);

module.exports = User;

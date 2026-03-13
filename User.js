const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({

    username: {
        type: String,
        unique: true
    },

    password: String,

    email: String,

    fullName: String

});

module.exports = mongoose.model("User", userSchema);
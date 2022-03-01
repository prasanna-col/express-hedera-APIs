var mongoose = require("mongoose");

var userDetailsSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true
    },
    username: {
        type: String,
        unique: true
    },
    gender: {
        type: String,
        default: "Not available"
    },
    nationality: {
        type: String,
        default: "Not available"
    },
    country_residence: {
        type: String,
        default: "Not available"
    },
    age: {
        type: Number,
        default: 0
    },
    profile_picture: {
        type: String,
        default: 'NA'
    }
});

module.exports = mongoose.model("UserDetails", userDetailsSchema);

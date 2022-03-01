var mongoose = require("mongoose");

var userAuthSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true
    },
    username: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    timestamp: {
        type: String,
        required: true
    },
    hederaPrivateKey: {
        type: String,

    },
    hederaAccountID: {
        type: String
    }
});

module.exports = mongoose.model("UserAuth", userAuthSchema);

var mongoose = require("mongoose");

var itemsSoldSchema = new mongoose.Schema({

    itemName: {
        type: String,
        default: "Not available"
    },
    itemPrice: {
        type: Number,
        default: 0
    },
    itemQuantity: {
        type: Number,
        default: 0
    },
    sellerUsername: {
        type: String,
        default: "Not available"
    },
    sellerEmail: {
        type: String,
        default: "Not available"
    },
    sellerStreetLocation: {
        type: String,
        default: "Not available"
    },
    sellerCityName: {
        type: String,
        default: "Not available"
    },
    sellerPinCode: {
        type: Number,
        default: "Not available"
    },

    sellerPhoneNo: {
        type: String,
        default: "Not available"
    },
    timestamp: {
        type: String,
        default: "Not available"
    }
});

module.exports = mongoose.model("itemsSold", itemsSoldSchema);

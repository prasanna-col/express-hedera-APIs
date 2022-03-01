var mongoose = require("mongoose");

var purchasedItemsSchema = new mongoose.Schema({

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
    buyerUsername: {
        type: String,
        default: "Not available"
    },
    buyerEmail: {
        type: String,
        default: "Not available"
    },
    buyerStreetLocation: {
        type: String,
        default: "Not available"
    },
    buyerCityName: {
        type: String,
        default: "Not available"
    },
    buyerPinCode: {
        type: Number,
        default: "Not available"
    },

    buyerPhoneNo: {
        type: String,
        default: "Not available"
    },
    timestamp: {
        type: String,
        default: "Not available"
    }
});

module.exports = mongoose.model("purchasedItems", purchasedItemsSchema);

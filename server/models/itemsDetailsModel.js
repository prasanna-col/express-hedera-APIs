var mongoose = require("mongoose");

var itemsDetailSchema = new mongoose.Schema({
    itemName: {
        type: String,
        unique: true
    },
    itemPrice: {
        type: Number,
        default: 0
    },
    itemSold: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'itemsSold'
    }],
    itemBought: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'purchasedItems'
    }]
});

module.exports = mongoose.model("itemsDetails", itemsDetailSchema);

const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const moment = require('moment-timezone');
const UserAuthModel = require("../../../models/userAuthModel");
const UserDetailsModel = require("../../../models/userDetailsModel");
const ItemsDetailModel = require("../../../models/itemsDetailsModel");
const PurchasedItemModel = require("../../../models/purchasedItems");
const ItemsSoldModel = require("../../../models/itemsSold");
const { body, validationResult } = require("express-validator");
const { validateApiSecret, isAuthenticated } = require("../auth/authHelper");
const { MY_ACCOUNT_ID, MY_PRIVATE_KEY, API_SECRET_KEY, TokenName } = require("../../constant");

//Hedera setup

const {
  Client,
  PrivateKey,
  AccountCreateTransaction,
  AccountBalanceQuery,
  Hbar,
  TransferTransaction
} = require("@hashgraph/sdk");

require("dotenv").config();


// Create a new Item

router.post('/createItem',
  validateApiSecret,
  isAuthenticated,
  async (req, res) => {
    try {

      const itemDetails = {
        itemName: req.body.itemName,
        itemPrice: req.body.itemPrice
      }

      const itemData = await ItemsDetailModel.create(itemDetails);
      if (itemData) {
        res.status(200).json({
          msg: "New item created",
          result: true
        })
      }
      else {
        res.status(400).json({
          error: "There was a problem while creating the new item",
          result: false
        })
      }
    } catch (err) {
      return res.status(500).json({
        msg: "There was a problem while creating the new item",
        result: false,
        err
      });
    }
  });


//Buy item from Krushi Gruha

router.post('/buyItem',
  validateApiSecret,
  isAuthenticated,
  async (req, res) => {
    try {

      const userAuthData = await UserAuthModel.find({ username: req.decoded.username });

      console.log("userAuthData --> ", userAuthData)
      //Grab Hedera testnet account ID and private key from .env file
      const myAccountId = userAuthData[0].hederaAccountID;
      const myPrivateKey = userAuthData[0].hederaPrivateKey;

      // If we weren't able to grab it, we should throw a new error
      if (myAccountId == null ||
        myPrivateKey == null) {
        throw new Error("Environment variables myAccountId and myPrivateKey must be present");
      }


      // Create connection to the Hedera network

      const client = Client.forTestnet();
      client.setOperator(myAccountId, myPrivateKey);
      console.log("buyitem req -->", req.body)
      let transferAmount = req.body.itemPrice * req.body.itemQuantity * 100000000;

      //Create the transfer transaction

      const transferTransactionResponse = await new TransferTransaction()
        .addHbarTransfer(myAccountId, Hbar.fromTinybars(-transferAmount))
        .addHbarTransfer(MY_ACCOUNT_ID, Hbar.fromTinybars(transferAmount))
        .execute(client);


      //Verify the transaction reached consensus
      const transactionReceipt = await transferTransactionResponse.getReceipt(client);
      console.log("The transfer transaction from my account to the new account was: " + transactionReceipt.status.toString());


      if (transactionReceipt.status == false) {
        return res.status(500).json({
          result: false,
          msg: "There was an error in hbar transfer"
        })
      }



      const details = {
        itemName: req.body.itemName,
        itemPrice: req.body.itemPrice,
        itemQuantity: req.body.itemQuantity,
        buyerStreetLocation: req.body.buyerStreetLocation,
        buyerUsername: req.decoded.username,
        buyerEmail: req.decoded.email,
        buyerCityName: req.body.buyerCityName,
        buyerPinCode: req.body.buyerPinCode,
        buyerPhoneNo: req.body.buyerPhoneNo,
        timestamp: moment().format('MMMM Do YYYY, h:mm:ss a')
      }


      const itemData = await PurchasedItemModel.create(details);
      if (itemData) {
        const itemsDetails = await ItemsDetailModel.findOneAndUpdate({ itemName: req.body.itemName }, {
          $push: {
            itemBought: itemData._id
          }
        })
        if (itemsDetails) {
          res.status(200).json({
            msg: "Item bought",
            result: true
          })
        }
        else {
          res.status(400).json({
            error: "Item name is invalid",
            result: false
          })
        }

      }
      else {
        res.status(400).json({
          error: "Failed to buy the item",
          result: false
        })
      }
    } catch (err) {
      console.log(err);
      return res.status(500).json({
        msg: "Failed to buy the item.",
        result: false,
        err
      });
    }
  });




//Sell item from Krushi Gruha

router.post('/sellItem',
  validateApiSecret,
  isAuthenticated,
  async (req, res) => {
    try {

      const userAuthData = await UserAuthModel.find({ username: req.decoded.username });

      if (userAuthData.length <= 0) {
        return res.status(500).json({
          result: false,
          msg: "There was a problem on the server"
        })
      }

      //Grab Hedera testnet account ID and private key from .env file
      const myAccountId = MY_ACCOUNT_ID;
      const myPrivateKey = MY_PRIVATE_KEY;

      // If we weren't able to grab it, we should throw a new error
      if (myAccountId == null ||
        myPrivateKey == null) {
        throw new Error("Environment variables myAccountId and myPrivateKey must be present");
      }


      // Create connection to the Hedera network

      const client = Client.forTestnet();
      client.setOperator(myAccountId, myPrivateKey);

      let transferAmount = req.body.itemPrice * req.body.itemQuantity * 100000000;

      //Create the transfer transaction

      const transferTransactionResponse = await new TransferTransaction()
        .addHbarTransfer(myAccountId, Hbar.fromTinybars(-transferAmount))
        .addHbarTransfer(userAuthData[0].hederaAccountID, Hbar.fromTinybars(transferAmount))
        .execute(client);


      //Verify the transaction reached consensus
      const transactionReceipt = await transferTransactionResponse.getReceipt(client);
      console.log("The transfer transaction from my account to the new account was: " + transactionReceipt.status.toString());

      if (transactionReceipt.status == false) {
        return res.status(500).json({
          result: false,
          msg: "There was an error in hbar transfer"
        })
      }


      const details = {
        itemName: req.body.itemName,
        itemPrice: req.body.itemPrice,
        itemQuantity: req.body.itemQuantity,
        sellerStreetLocation: req.body.sellerStreetLocation,
        sellerUsername: req.decoded.username,
        sellerEmail: req.decoded.email,
        sellerCityName: req.body.sellerCityName,
        sellerPinCode: req.body.sellerPinCode,
        sellerPhoneNo: req.body.sellerPhoneNo,
        timestamp: moment().format('MMMM Do YYYY, h:mm:ss a')
      }

      const itemData = await ItemsSoldModel.create(details);
      if (itemData) {
        const itemsDetails = await ItemsDetailModel.findOneAndUpdate({ itemName: req.body.itemName }, {
          $push: {
            itemSold: itemData._id
          }
        })
        if (itemsDetails) {
          res.status(200).json({
            msg: "Item sold",
            result: true
          })
        }
        else {
          res.status(400).json({
            error: "Item name is invalid",
            result: false
          })
        }

      }
      else {
        res.status(400).json({
          error: "Failed to sell the item",
          result: false
        })
      }
    } catch (err) {
      console.log(err);
      return res.status(500).json({
        msg: "Failed to sell the item",
        result: false,
        err
      });
    }
  });


// Find User's past orders

router.get('/getPastOrders',
  validateApiSecret,
  isAuthenticated,
  async (req, res) => {
    try {
      const itemData = await PurchasedItemModel.find({ $or: [{ buyerEmail: req.decoded.email }, { buyerUsername: req.decoded.username }] });
      if (itemData.length > 0) {
        res.status(200).json({
          msg: "User past orders on prasanna fetched",
          result: true,
          data: itemData
        })
      }
      else {
        res.status(404).json({
          error: "No orders found for the given user",
          result: false
        })
      }
    } catch (err) {
      console.log(err);
      return res.status(500).json({
        msg: "There was a problem fetching users past orders",
        result: false,
        err
      });
    }
  });


// Find all the items that the user has sold on the KrishiGruha platform

router.get('/getItemsSold',
  validateApiSecret,
  isAuthenticated,
  async (req, res) => {
    try {
      const itemData = await ItemsSoldModel.find({ $or: [{ sellerEmail: req.decoded.email }, { sellerUsername: req.decoded.username }] });
      if (itemData.length > 0) {
        res.status(200).json({
          msg: "All the items sold on prasanna by the user fetched",
          result: true,
          data: itemData
        })
      }
      else {
        res.status(404).json({
          error: "No items were sold by the given user",
          result: false
        })
      }
    } catch (err) {
      console.log(err);
      return res.status(500).json({
        msg: "There was a problem fetching the list of items that the user has sold",
        result: false,
        err
      });
    }
  });


module.exports = router;




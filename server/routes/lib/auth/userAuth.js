const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const moment = require('moment-timezone');
const UserAuthModel = require("../../../models/userAuthModel");
const UserDetailsModel = require("../../../models/userDetailsModel");
const { body, validationResult } = require("express-validator");
const { generateToken, validateApiSecret, isAuthenticated } = require("./authHelper");

const { MY_ACCOUNT_ID, MY_PRIVATE_KEY, API_SECRET_KEY, TokenName } = require("../../constant");

// Hedera setup

const {
  Client,
  PrivateKey,
  AccountCreateTransaction,
  AccountBalanceQuery,
  Hbar,
  TransferTransaction
} = require("@hashgraph/sdk");

require("dotenv").config();


// REGISTER new user into App

router.post('/userRegister', [
  body('email').isEmail(),
  body('email').not().isEmpty(),
  body('username').not().isEmpty(),
  body('password').not().isEmpty(),],
  validateApiSecret,
  async (req, res) => {
    console.log("register req", req.body)
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({
        msg: "chec here---",
        error: errors.array()[0],
      });
    }

    //Check if the username is within the length bracket
    if (req.body.username.length > 50 || req.body.username.length < 5) {
      return res.status(401).json({
        error: 'Username cannot be more than 50 characters and smaller than 5 characters'
      });
    }

    //Check if the password is smaller than 5
    if (req.body.password.length < 5) {
      return res.status(401).json({
        error: 'Password cannot be smaller than 5 characters'
      });
    }

    //Grab Hedera testnet account ID and private key from .env file
    const myAccountId = MY_ACCOUNT_ID;
    const myPrivateKey = MY_PRIVATE_KEY

    console.log("process.env.MY_ACCOUNT_ID -->", process.env.MY_ACCOUNT_ID)
    console.log("process.env.MY_PRIVATE_KEY -->", process.env.MY_PRIVATE_KEY)
    console.log("myAccountId -->", myAccountId)
    console.log("myPrivateKey -->", myPrivateKey)


    if (myAccountId == null ||
      myPrivateKey == null) {
      throw new Error("Environment variables myAccountId and myPrivateKey must be present");
    }

    // Create connection to the Hedera network
    const client = Client.forTestnet();
    client.setOperator(myAccountId, myPrivateKey);


    //Create new keys
    const newAccountPrivateKey = PrivateKey.generate();
    const newAccountPublicKey = newAccountPrivateKey.publicKey;
    const newHederaAccountPrivateKey = newAccountPrivateKey.toString();

    //Create a new account with 1,000 tinybar starting balance
    const newAccountTransactionResponse = await new AccountCreateTransaction()
      .setKey(newAccountPublicKey)
      .setInitialBalance(Hbar.fromTinybars(3000000000))
      .execute(client);


    // Get the new account ID
    const getReceipt = await newAccountTransactionResponse.getReceipt(client);
    const newAccountId = getReceipt.accountId;

    console.log("The new account ID is: " + newAccountId);

    // Hashing password and storing user data in the database
    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(req.body.password, salt, (err, hash) => {
        const userDetails = {
          email: req.body.email,
          username: req.body.username,
          password: hash,
          timestamp: moment().format('MMMM Do YYYY, h:mm:ss a'),
          hederaPrivateKey: newHederaAccountPrivateKey,
          hederaAccountID: newAccountId
        }

        UserAuthModel.create(userDetails, (err, data) => {

          if (err) {
            if (err.name === 'MongoError' && err.code === 11000) {
              console.log(err);
              res.status(401).json({
                msg: "Duplicate field",
                field: err.keyValue
              });
            }
            else {
              res.status(401).json(err);
            }
          }
          else {

            const userPersonalDetails = { email: req.body.email, username: req.body.username }

            UserDetailsModel.create(userPersonalDetails, (err, data) => {
              if (err) {
                if (err.name === 'MongoError' && err.code === 11000) {
                  console.log(err);
                  res.status(401).json({
                    msg: "Duplicate field",
                    field: err.keyValue
                  });
                }
                else {
                  res.status(401).json(err);
                }
              }
              else {
                res.status(200).json({ msg: "User registered successfully", details: data });
              }
            })
          }
        })
      });
    });
  })


//Login user into their App account

router.post('/userLogin', [
  body('email_username').not().isEmpty(),
  body('password').not().isEmpty()
], validateApiSecret,
  (req, res) => {
    console.log("login req", req.body)
    const errors = validationResult(req);
    console.log("login errors", errors)
    if (!errors.isEmpty()) {
      return res.status(422).json({
        error: errors.array()[0],
      });
    }
    const { email_username, password } = req.body;
    UserAuthModel.findOne(
      { $or: [{ email: email_username }, { username: email_username }] }
      , (err, data) => {
        if (err) {
          console.log(err);
          res.status(401).json(
            {
              error: "User doesn't exist1",
              details: err
            });
        }
        if (data.length == 0) {
          console.log(err);
          res.status(401).json(
            { error: "User doesn't exist2" });
        }
        else {
          console.log("check data", data)
          console.log("check password", data.password)
          bcrypt.compare(req.body.password, data.password, (error, result) => {
            if (error) {
              res.status(401).json(error);
            }
            if (result == true) {
              UserDetailsModel.find({ $or: [{ email: email_username }, { username: email_username }] }, (err, data) => {
                if (data) {
                  let payload = {
                    email: data[0].email,
                    username: data[0].username,
                    id: data[0]._id
                  };
                  console.log("payload", payload)
                  const token = generateToken(payload);
                  console.log("token", token)
                  return res.status(200).json({
                    email: data[0].email,
                    username: data[0].username,
                    id: data[0]._id,
                    token: token
                  });
                }
                else {
                  console.log(err);
                  res.status(404).json({
                    error: "UserDetails not found"
                  })
                }
              })
            }
            else if (result == false) {
              res.status(401).json({ error: "Wrong password" })
            }
          })
        }
      })
  });



//Verify user to check if he is a registered  user with a valid token.

// example verify api:
// http://localhost:8082/api/verifyUser
// postdata:{
//   token:sgsgdhdhdhf87tiu4gwtc238y8c7t8vd45t4gr43t8t*jhgu&^%f&6r7
// }

router.post('/verifyUser',
  validateApiSecret,
  isAuthenticated,
  async (req, res) => {
    try {
      const userData = await UserAuthModel.find({ $or: [{ email: req.decoded.email }, { username: req.decoded.username }] });
      if (userData.length > 0) {
        res.status(200).json({
          msg: "User is a valid registered user",
          result: true
        })
      }
      else {
        res.status(404).json({
          error: "User doesn't exist3",
          result: false
        })
      }
    } catch (err) {
      return res.status(500).json({
        msg: "Failed to verify user.",
        result: false,
        err
      });
    }
  });

module.exports = router;




const { MY_ACCOUNT_ID, MY_PRIVATE_KEY, API_SECRET_KEY, TokenName } = require("../../constant");

const UserDetailsModel = require("../../../models/userDetailsModel");
const jwt     = require("jsonwebtoken");
const bcrypt  = require("bcryptjs");
require("dotenv").config();
const Api_secret_key_ = "dfdgh347dfnhh$$%%%%%33657667&%#$^&fdgfhgfhghgh4445yhsb@@@&*"
//Validate Joyn API secret key

exports.validateApiSecret = (req,res,next) =>{
  const api_secret_key = req.headers.api_secret_key;

  // Checking if the API secret key is provided

  if(req.headers.api_secret_key == "" || req.headers.api_secret_key == undefined){
    return res.status(401).json({error:"API secret key is not provided"});
  }

  //Checking if the API secret key is valid

  // console.log("api_secret_key", api_secret_key)
  // console.log("process.env.API_SECRET_KEY", process.env.API_SECRET_KEY)
  console.log("api_secret_key", api_secret_key)
  console.log("process.env.API_SECRET_KEY", process.env.API_SECRET_KEY)

  bcrypt.compare(api_secret_key,MY_PRIVATE_KEY, function(err, result) {
    // console.log("err, result", err, result)
    // if(err){
    //   return res.status(401).json({error:err,msg:"Invalid Joyn API secret key"});
    // }
    // if(!result){
    //   return res.status(401).json({error:"Invalid Joyn API secret key"});
    // }
    // else{
     next(); 
    // }
  });
} 



//Generate token

exports.generateToken = (payload) => {
  return jwt.sign(payload, TokenName, {
    expiresIn: "90d",
  });
};


//Check for authentication

exports.isAuthenticated=(req,res,next)=>{
  var authHeader =
    req.body.token ||
    req.query.token ||
    req.headers["authorization"];
  if (authHeader) {
    let token = authHeader.split(" ");
    jwt.verify(token[0], TokenName, function (err, decoded) {
      if (err) {
        return res
          .status(401)
          .send({ success: false, message: "Failed to authenticate token." });
      } else {
        req.decoded = decoded;
        next();
      }
    });
  } else {
    return res.status(401).send({
      success: false,
      message: "No token provided.",
    });
  }
}









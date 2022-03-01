const express       =   require('express');
const bodyparser    =   require('body-parser');
const app           =   express();
const cors          =   require("cors");
const path          =   require('path');
const moment        =   require('moment-timezone');
const userAuth      =   require('./lib/auth/userAuth');
const itemsAPI      =   require('./lib/api/itemsapi');


//BODY PARSER PRESET

app.use(bodyparser.json());

app.use(bodyparser.urlencoded({
    extended: true
}));

app.use(bodyparser.text({ limit: '200mb' }));


// CORS PRESETS

app.use(cors());

app.use(express.static("docs"));
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin,X-Requested-With,Content-Type,Accept,Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,PUT,OPTIONS');
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});


// Timezone setup

moment.tz.setDefault("Asia/Kolkata");



// User Login/Signup

app.use('/api',userAuth);


// Items API

app.use('/api',itemsAPI);




module.exports = app;
/* eslint-disable no-restricted-syntax */
require('dotenv').config();
const express = require('express');
const app = express();
const port = process.env.PORT || 3333;
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { nanoid } = require('nanoid');
const reservedUsernames = require('./helpers/reservedUsernames');
const { verifyPushToken } = require('./helpers/expoNotifications');
const { sendExpoNotifications } = require('./helpers/expoNotifications');

// JWT
const JWT = require('./helpers/jwt');

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  next();
});

// Nodemailer
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_SERVER,
  port: 587,
  secure: false, // upgrade later with STARTTLS
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD
  }
});
transporter.verify(function (error, success) {
  if (error) {
    console.log("Email server error!")
    console.log(error);
  } else {
    console.log("Email server is ready to take our messages");
  }
});

// Firebase
var firebaseAdmin = require("firebase-admin");
var serviceAccount = require("./firebase.json");
firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert(serviceAccount),
  databaseURL: "https://witchnet-app.firebaseio.com"
});

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());

const configDatabase = require('./config/database.js');
const mongoose = require('mongoose');
mongoose.connect(configDatabase.url, { useNewUrlParser: true, useUnifiedTopology: true });
const ObjectId = mongoose.Types.ObjectId;
const User = require('./models/user');

// const notifier = require('./helpers/notifier')

const sendError = (message) => {
  return {
    error: message,
  };
};

const sendResponse = (data, status, message) => {
  return data;
};

function isObjectIdValid(string) {
  if (ObjectId.isValid(string)) {
    if (String(new ObjectId(string)) === string) {
      return true;
    }
  }
  return false;
}

async function hashPassword(password) {
  const saltRounds = 10;
  const hashedPassword = await new Promise((resolve, reject) => {
    bcrypt.hash(password, saltRounds, function (err, hash) {
      if (err) reject(err)
      resolve(hash)
    });
  })
  return hashedPassword
}

app.use('/api/*', async (req, res, next) => {
  console.log(req.originalUrl)
  console.log(req.headers)
  // We don't need to check headers for the login route
  if (req.originalUrl === '/api/login' || req.originalUrl === '/api/register') {
    console.log('Login/register route, proceed')
    return next()
  }
  // Immediately reject all unauthorized requests
  if (!req.headers.authorization) {
    console.log("JWT Token not supplied")
    return res.status(401).send(sendError('Not authorized to access this API'))
  }
  let verifyResult = JWT.verify(req.headers.authorization, { issuer: 'sweet.sh' });
  if (!verifyResult) {
    console.log("JWT Token failed verification", req.headers.authorization)
    return res.status(401).send(sendError('Not authorized to access this API'))
  }
  console.log("We all good!")
  console.log(verifyResult)
  req.user = (await User.findOne({ _id: verifyResult.id }));
  if (!req.user) {
    return res.status(404).send(sendError('No matching user registered in API'))
  }
  next()
})

app.post('/api/expo_token/register', async (req, res) => {
  console.log('Registering Expo token!', req.body.token)
  if (!req.body.token) {
    return res.status(400).send(sendError('No token submitted'));
  }
  if (!verifyPushToken(req.body.token)) {
    return res.status(400).send(sendError('Token invalid'));
  }
  req.user.expoPushTokens.push(req.body.token);
  await req.user.save()
    .catch(error => {
      console.error(error);
      return res.status(500).send(sendError('Error saving push token to database'));
    })
  console.log('Registered!')
  return res.sendStatus(200);
});

app.post('/api/register', async (req, res) => {
  // Check if data has been submitted
  if (!req.body.email || !req.body.password || !req.body.username) {
    return res.status(406).send('Required fields (email, password, username) blank.');
  }
  // Check if a user with this username already exists
  const existingUsername = await (User.findOne({ username: req.body.username }));
  if (existingUsername) {
    console.log('Username exists.')
    return res.status(403).send('Sorry, this username is unavailable.');
  }
  // Check if this username is in the list of reserved usernames
  if (reservedUsernames.includes(req.body.username)) {
    console.log('Username reserved.')
    return res.status(403).send('Sorry, this username is unavailable.');
  }
  // Check if a user with this email already exists
  const existingEmail = await (User.findOne({ email: req.body.email }));
  if (existingEmail) {
    console.log('Email exists.')
    return res.status(403).send('An account with this email already exists. Is it yours?');
  }
  const verificationToken = nanoid();
  const newUser = new User({
    email: req.body.email,
    password: await hashPassword(req.body.password),
    username: req.body.username,
    joined: new Date(),
  });
  const savedUser = await newUser.save();
  const sentEmail = await transporter.sendMail({
    from: '"WitchNet" <contact@witchnet.net>',
    to: req.body.email,
    subject: "Welcome to WitchNet!",
    text: 'Hi ' + req.body.username + '!\n\nYou are receiving this because you have created a new account on WitchNet with this email.\n\n' +
      'Welcome! Have fun and be safe.\n\n' +
      'If you have any problems or questions, just reply to this email.\n\n' +
      'Love,\n\n' +
      'WitchNet'
  });
  if (!savedUser || !sentEmail) {
    return res.status(500).send('There has been a problem processing your registration.');
  }
  return res.sendStatus(200);
});

app.post('/api/login', async (req, res) => {
  // Check if data has been submitted
  if (!req.body.email || !req.body.password) {
    console.log("Login data missing")
    return res.status(401).send(sendError('User not authenticated'));
  }
  const user = await (User.findOne({ email: req.body.email }))
    .catch(error => {
      console.error(error);
      return res.status(401).send(sendError('User not authenticated'));
    });
  // If no user found
  if (!user) {
    console.log("No user found")
    return res.status(401).send(sendError('User not authenticated'));
  }
  // console.log("Is verified:", user.isVerified)
  // if (!user.isVerified) {
  //   console.log("User not verified")
  //   return res.status(401).send(sendError('This account has not been verified.'));
  // }
  // Compare submitted password to database hash
  bcrypt.compare(req.body.password, user.password, async (err, result) => {
    if (!result) {
      console.log("Password verification failed")
      return res.status(401).send(sendError('User not authenticated'));
    }
    // Create the Firebase token
    const firebaseToken = await firebaseAdmin.auth().createCustomToken(user._id.toString())
      .then(function (customToken) {
        return customToken;
      })
      .catch(function (error) {
        console.log('Error creating Firebase token:', error);
      });
    const jwtOptions = {
      issuer: 'sweet.sh',
    }
    return res.status(200).send({ firebaseToken: firebaseToken, token: JWT.sign({ id: user._id.toString() }, jwtOptions) });
  });
});

app.get('/api/user/:identifier', async (req, res) => {
  // req.params.identifier might be a username OR a MongoDB _id string. We need to work
  // out which it is:
  let userQuery;
  if (isObjectIdValid(req.params.identifier)) {
    userQuery = { _id: req.params.identifier };
  } else {
    userQuery = { username: req.params.identifier };
  }
  const userData = await User.findOne(userQuery, 'email username displayName acceptedCodeOfConduct settings')
    .catch(err => {
      return res.status(500).send(sendError('Error fetching user'));
    });
  if (!userData) {
    return res.status(404).send(sendError('User not found'));
  }
  return res.status(200).send(userData);
});

app.post('/api/settings', (req, res) => {
  const newSettings = req.body;
  console.log(newSettings)
  if (!newSettings) {
    return res.status(406).send(sendError(406, 'No new settings provided'));
  }
  req.user.settings = { ...req.user.settings, ...req.body }
  req.user.save()
    .then(user => {
      return res.status(200).send(sendResponse(user, 200))
    })
    .catch(error => {
      console.log(error);
      return res.status(500).send(sendError(500, 'Error saving new settings'));
    })
});

app.post('/api/notification', async (req, res) => {
  const notification = req.body;
  console.log(notification)
  const notificationLength = 64;
  let usersToNotify;
  let notificationTitle;
  let notificationBody;
  let notificationPermission;
  switch (notification.subject) {
    case 'summon-coven':
      const titleDictionary = {
        'summon-coven': `${req.user.settings.displayName || req.user.username} is summoning the Coven`
      }
      const purposeDictionary = {
        'advice': 'looking for advice',
        'cast-spell': 'casting a spell',
        'perform-ritual': 'performing a ritual',
        'read-tarot': 'reading Tarot',
        'cast-runes': 'casting runes'
      }
      const bodyDictionary = {
        'summon-coven': `${req.user.settings.displayName || req.user.username} is ${purposeDictionary[notification.purpose]}.`
      }
      usersToNotify = await User.find({ _id: { $ne: req.user._id } });
      notificationTitle = titleDictionary[notification.subject];
      notificationBody = bodyDictionary[notification.subject];
      notificationPermission = 'sendSummoningNotifications';
      break;
    case 'new-message':
      usersToNotify = await User.find({ $and: [{ _id: { $in: notification.usersToNotify } }, { _id: { $ne: req.user._id } }] });
      notificationTitle = `${notification.displayName || notification.username} @ ${notification.summonerDisplayName || notification.summonerUsername}'s summoning`;
      notificationBody = (notification.message.length > notificationLength) ? notification.message.substr(0, notificationLength - 1) + '&hellip;' : notification.message;
      notificationPermission = 'sendChatNotifications';
      break;
    case 'drew-tarot-card':
      usersToNotify = await User.find({ _id: { $ne: req.user._id } });
      notificationTitle = `${notification.displayName || notification.username} is drawing a Tarot card`;
      notificationBody = `${notification.displayName || notification.username} drew ${notification.cardName}.`;
      notificationPermission = 'sendTarotNotifications';
  }
  const tokensToNotify = [];
  if (usersToNotify) {
    usersToNotify.forEach(async (notifiedUser) => {
      if (notifiedUser.expoPushTokens.length > 0 && notifiedUser.settings[notificationPermission] === true) {
        // The app tends to try and send the same token multiple times for some reason, so this is
        // a perfect place to clean out the push tokens array.
        const uniqueTokens = [...new Set(notifiedUser.expoPushTokens)]
        tokensToNotify.push(...uniqueTokens);
        notifiedUser.expoPushTokens = uniqueTokens;
        await notifiedUser.save()
          .catch(error => {
            console.error("Error saving user after de-depulicating Expo push tokens array:", error)
          });
      }
    })
    if (tokensToNotify.length) {
      sendExpoNotifications({
        pushTokens: tokensToNotify,
        title: notificationTitle,
        body: notificationBody
      });
    }
  }
  return res.sendStatus(200);
});

app.post('/api/report', async (req, res) => {
  console.log('======REPORT======');
  console.log(req.body)
  console.log('==================')
  const sentEmail = await transporter.sendMail({
    from: '"WitchNet" <contact@witchnet.net>',
    to: '"Raphael Kabo" <mail@raphaelkabo.com>',
    subject: "WitchNet User Report",
    text: JSON.stringify(req.body)
  });
  return res.sendStatus(200);
});

app.post('/api/update-message', async (req, res) => {
  const updateMessage = {
    version: 1,
    content: 'Hello\n\nThere.'
  }
  if (req.user.mostRecentUpdateMessageRead.version >= updateMessage.version) {
    return res.sendStatus(204);
  }
  return res.status(200).send(updateMessage.content);

});

app.listen(port);

console.log('Server booting on default port: ' + port);
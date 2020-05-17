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
transporter.verify(function(error, success) {
	if (error) {
		console.log("Email server error!")
		console.log(error); 
	} else {
		console.log("Email server is ready to take our messages");
	}
});

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());

const configDatabase = require('./config/database.js');
const mongoose = require('mongoose');
mongoose.connect(configDatabase.url, { useNewUrlParser: true, useUnifiedTopology: true });
const ObjectId = mongoose.Types.ObjectId;

// const notifier = require('./helpers/notifier')

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
    return res.status(401).send(sendError(401, 'Not authorized to access this API'))
  }
  let verifyResult = JWT.verify(req.headers.authorization, { issuer: 'sweet.sh' });
  if (!verifyResult) {
    console.log("JWT Token failed verification", req.headers.authorization)
    return res.status(401).send(sendError(401, 'Not authorized to access this API'))
  }
  console.log("We all good!")
  console.log(verifyResult)
  req.user = (await User.findOne({ _id: verifyResult.id }));
  if (!req.user) {
    return res.status(404).send(sendError(404, 'No matching user registered in API'))
  }
  next()
})

app.post('/api/expo_token/register', async (req, res) => {
  console.log('Registering Expo token!', req.body.token)
  if (!req.body.token) {
    return res.status(400).send(sendError(400, 'No token submitted'));
  }
  if (!verifyPushToken(req.body.token)) {
    return res.status(400).send(sendError(400, 'Token invalid'));
  }
  req.user.expoPushTokens.push(req.body.token);
  await req.user.save()
    .catch(error => {
      console.error(error);
      return res.status(500).send(sendError(500, 'Error saving push token to database'));
    })
  console.log('Registered!')
  return res.sendStatus(200);
});

app.post('/api/register', async (req, res) => {
  // Check if data has been submitted
  if (!req.body.email || !req.body.password || !req.body.username) {
    return res.status(406).send(sendError(406, 'Required fields (email, password, username) blank.'));
  }
  // Check if a user with this username already exists
  const existingUsername = await (User.findOne({ username: req.body.username }));
  if (existingUsername) {
    return res.status(403).send(sendError(403, 'Sorry, this username is unavailable.'));
  }
  // Check if this username is in the list of reserved usernames
  if (reservedUsernames.includes(req.body.username)) {
    return res.status(403).send(sendError(403, 'Sorry, this username is unavailable.'));
  }
  // Check if a user with this email already exists
  const existingEmail = await (User.findOne({ email: req.body.email }));
  if (existingEmail) {
    return res.status(403).send(sendError(403, 'An account with this email already exists. Is it yours?'));
  }
  const verificationToken = nanoid();
  const newUser = new User({
    email: req.body.email,
    password: await hashPassword(req.body.password),
    username: req.body.username,
    joined: new Date(),
    verificationToken: verificationToken,
    verificationTokenExpiry: Date.now() + 3600000 // 1 hour
  });
  const savedUser = await newUser.save();
  const sweetbotFollow = new Relationship({
    from: req.body.email,
    to: 'support@sweet.sh',
    toUser: '5c962bccf0b0d14286e99b68',
    fromUser: newUser._id,
    value: 'follow'
  });
  const savedFollow = await sweetbotFollow.save();
  const sentEmail = await transporter.sendMail({
    from: '"Sweet Support" <support@sweet.sh>',
    to: req.body.email,
    subject: "Sweet - New user verification",
    text: 'Hi! You are receiving this because you have created a new account on sweet with this email.\n\n' +
    'Please click on the following link, or paste it into your browser, to verify your email:\n\n' +
    'https://sweet.sh/verify-email/' + verificationToken + '\n\n' +
    'If you did not create an account on sweet, please ignore and delete this email. The token will expire in an hour.\n'
  });
  if (!savedUser || !savedFollow || !sentEmail) {
    return res.status(500).send(sendError(500, 'There has been a problem processing your registration.'));
  }
  return res.sendStatus(200);
});

app.post('/api/login', async (req, res) => {
  // Check if data has been submitted
  if (!req.body.email || !req.body.password) {
    console.log("Login data missing")
    return res.status(401).send(sendError(401, 'User not authenticated'));
  }
  const user = await (User.findOne({ email: req.body.email }))
    .catch(error => {
      console.error(error);
      return res.status(401).send(sendError(401, 'User not authenticated'));
    });
  // If no user found
  if (!user) {
    console.log("No user found")
    return res.status(401).send(sendError(401, 'User not authenticated'));
  }
  console.log("Is verified:", user.isVerified)
  if (!user.isVerified) {
    console.log("User not verified")
    return res.status(401).send(sendError(401, 'This account has not been verified.'));
  }
  // Compare submitted password to database hash
  bcrypt.compare(req.body.password, user.password, (err, result) => {
    if (!result) {
      console.log("Password verification failed")
      return res.status(401).send(sendError(401, 'User not authenticated'));
    }
    const jwtOptions = {
      issuer: 'sweet.sh',
    }
    return res.status(200).send(sendResponse(JWT.sign({ id: user._id.toString() }, jwtOptions), 200));
  });
});

app.listen(port);

console.log('Server booting on default port: ' + port);
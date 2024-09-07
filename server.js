const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jwt-simple');
const crypto = require('crypto');
const session = require('express-session');
const { User, Client, AuthCode } = require('./models/model');
const cors = require('cors');

const app = express();
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


// Set up session middleware
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,  // Set this to `true` if you’re using HTTPS
    httpOnly: true,
    sameSite: 'lax' // Adjust based on your needs
  }
}));

// Connect to MongoDB
mongoose.connect('mongodb://localhost/oauth2-example', () => {
  console.log("Connected to MongoDb")
});

// Utility function to generate random strings
function generateRandomString(length) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}


function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  } else {
    // Redirect to login if the user is not authenticated
    return res.redirect(`/login?redirect_uri=${req.originalUrl}`);
  }
}

// 1. User Registration (for testing purposes)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Hashing password (hashing mechanism should be applied here)
  const user = new User({ username, password });
  await user.save();

  res.json({ message: 'User registered successfully' });
});

// 2. User Login
app.get('/login', (req, res) => {
  // Render a simple form for testing
  res.send(`
    <form method="POST" action="/login">
      Username: <input name="username" required/>
      <button type="submit">Login</button>
    </form>
  `);
});


app.post('/login', async (req, res) => {
  const username = req.body.username
  console.log(username)
  const user = await User.findOne({ username });

  if (user) {
    // Authenticate the user and create a session
    req.session.user = user;

    // Redirect the user back to the original requested URL (e.g., /authorize)
    const redirectUri = req.query.redirect_uri || '/';
    return res.redirect(redirectUri);
  } else {
    res.status(401).send('Invalid username or password');
  }
});

// 3. Client Registration
app.post('/clients/register', async (req, res) => {
  const { redirectUris, grants } = req.body;
  const client = new Client({
    clientId: generateRandomString(16),
    clientSecret: generateRandomString(32),
    redirectUris,
    grants
  });
  await client.save();
  res.json({ clientId: client.clientId, clientSecret: client.clientSecret });
});

// 4. Authorization Code Grant Flow (with dynamic user session)
app.get('/authorize', ensureAuthenticated, async (req, res) => {
  const { response_type, client_id, redirect_uri, state } = req.query;

  // Find client and validate redirect URI
  const client = await Client.findOne({ clientId: client_id });
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'Invalid client or redirect URI' });
  }

  // Generate authorization code
  const code = generateRandomString(32);
  const authCode = new AuthCode({
    code,
    clientId: client_id,
    userId: req.session.user._id,  // Use authenticated user's ID
    redirectUri: redirect_uri,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000)  // 5 minutes expiry
  });
  await authCode.save();

  res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
});

// 5. Exchange Authorization Code for Access Token
app.post('/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

  // Validate client credentials
  const client = await Client.findOne({ clientId: client_id, clientSecret: client_secret });
  if (!client) return res.status(401).json({ error: 'Invalid client credentials' });

  if (grant_type === 'authorization_code') {
    const authCode = await AuthCode.findOne({ code, clientId: client_id, redirectUri: redirect_uri });
    if (!authCode || authCode.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired authorization code' });
    }

    // Generate access token and refresh token
    const accessToken = jwt.encode({ userId: authCode.userId, clientId: client_id }, 'access_token_secret', 'HS256', { expiresIn: '1h' });
    const refreshToken = jwt.encode({ userId: authCode.userId, clientId: client_id }, 'refresh_token_secret', 'HS256', { expiresIn: '7d' });

    res.json({ accessToken, refreshToken });
    await AuthCode.deleteOne({ code });  // Clean up authorization code after use
  } else {
    res.status(400).json({ error: 'Unsupported grant type' });
  }
});

// 6. Refresh Access Token
app.post('/token/refresh', async (req, res) => {
  const { grant_type, refresh_token, client_id, client_secret } = req.body;

  // Validate client credentials
  const client = await Client.findOne({ clientId: client_id, clientSecret: client_secret });
  if (!client) return res.status(401).json({ error: 'Invalid client credentials' });

  if (grant_type === 'refresh_token') {
    try {
      const decoded = jwt.decode(refresh_token, 'refresh_token_secret');
      const accessToken = jwt.encode({ userId: decoded.userId, clientId: client_id }, 'access_token_secret', 'HS256', { expiresIn: '1h' });
      const newRefreshToken = jwt.encode({ userId: decoded.userId, clientId: client_id }, 'refresh_token_secret', 'HS256', { expiresIn: '7d' });
      res.json({ accessToken, refreshToken: newRefreshToken });
    } catch (err) {
      res.status(400).json({ error: 'Invalid refresh token' });
    }
  } else {
    res.status(400).json({ error: 'Unsupported grant type' });
  }
});

// 7. Protect a Resource
app.get('/resource', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const decoded = jwt.decode(token, 'access_token_secret');
    // Here you would check if the token is valid and if the user has access to the requested resource
    res.json({ message: 'Access granted', userId: decoded.userId });
  } catch (err) {
    res.status(401).json({ error: 'Invalid access token' });
  }
});

// Start the server
app.listen(3000, () => {
  console.log('OAuth 2.0 server running on http://localhost:3000');
});

'use strict';

require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const helmet = require('helmet');
const { NODE_ENV } = require('./config');
const foldersRouter = require('./folders/folders_router');
const notesRouter = require('./notes/notes_router');
const jwt = require('json-web-token');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const app = express();

const morganOption = NODE_ENV === 'production' ? 'tiny' : 'common';

// standard middleware
app.use(morgan(morganOption));
app.use(helmet());
app.use(cors());
app.use(cookieParser());
app.use(bodyParser.json());

let users = {
  ryan: { username: 'ryan', password: 'password' },
};

app.post('/login', (req, res) => {
  console.log(req.body);
  const username = req.body.username;
  const password = req.body.password;
  if (!username || !password) {
    res.status(422).json({ msg: 'Missing Information' });
  }
  if (!users[username]) {
    res.status(403).json({ msg: 'User doesnt exist' });
  }
  let accessToken = jwt.sign(
    { username: req.body.username },
    process.env.ACCESS_TOKEN_SECRET,
    {
      algorithm: 'HS256',
      experiesIn: process.env.ACCESS_TOKEN_lIFE,
    }
  );
  let refreshToken = jwt.sign(
    { username: req.body.username },
    process.env.REFRESH_TOKEN_SECRET,
    {
      algorithm: 'HS256',
      experiesIn: process.env.REFRESH_TOKEN_LIFE,
    }
  );
  users[username].refreshToken = refreshToken;
  res.cookie('noteful-auth-token', accessToken, {
    secure: true,
    httpOnly: true,
  });
  res.send();
});

app.get('/refreshToken', function (req, res) => {
  let accessToken = req.cookies['noteful-auth-token'];
  if (!accessToken) {
    res.status(403).json({ msg: 'Access token is missing' });
  }

  let accessVerification = null;
  try {
    accessVerification = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET
    );
  } catch (e) {
    res.status(403).send();
  }

  let refreshVerify = null;
  try {
    refreshVerify = jwt.verify(
      users[username].refreshToken,
      process.env.ACCESS_TOKEN_SECRET
    );
  } catch (e) {
    res.status(403).send();
  }

  let newAccessToken = jwt.sign({ username }, process.env.ACCESS_TOKEN_SECRET, {
    algorithm: 'HS256',
    experiesIn: process.env.ACCESS_TOKEN_lIFE,
  });
  let newRefreshToken = jwt.sign(
    { username },
    process.env.REFRESH_TOKEN_SECRET,
    {
      algorithm: 'HS256',
      experiesIn: process.env.REFRESH_TOKEN_LIFE,
    }
  );
  users[username].refreshToken = newRefreshToken;
  res.cookie('noteful-auth-token', newAccessToken, {
    secure: true,
    httpOnly: true,
  });
  res.send();
});

const verifyToken = (req, res, next) => {
  let accessToken = req.cookies['noteful-auth-token'];
  if (!accessToken) {
    res.status(403).json({ msg: 'Access token is missing' });
  }

  let payload = null;
  try {
    payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    next();
  } catch (e) {
    res.status(403).send();
  }
};

app.use(verifyToken);

// default route
// routes for folders and notes
app.use('/api/folders', foldersRouter);
app.use('/api/notes', notesRouter);

app.get('/', (req, res) => {
  res.send('Hello, world!');
});

// error handlers
app.use(function errorHandler(error, req, res, next) {
  let response;
  if (NODE_ENV === 'production') {
    response = {
      error: {
        message: 'server error, internal error please submit a bug report',
      },
    };
  } else {
    console.error(error);
    response = { message: error.message, error };
  }
  res.status(500).json(response);
});

module.exports = app;

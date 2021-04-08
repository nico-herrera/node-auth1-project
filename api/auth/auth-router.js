// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router();
const Middleware = require('./auth-middleware');
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { json } = require('express');

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

  router.post('/register', Middleware.checkPasswordLength, Middleware.checkUsernameFree, async (req, res, next) => {
    const user = req.body;

    const hash = bcrypt.hashSync(user.password, 8);
    user.password = hash;
    try {
      const saved = await Users.add(user);
      res.status(200).json(saved);
    } catch (err) {
      next(err)
    }
  })


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

  router.post('/login', Middleware.checkUsernameExists, async (req, res, next) => {
    const {username, password} = req.body;

    try {
      const user = await Users.findBy({username}).first();

      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({message: `Welcome ${user.username}`});
      } else {
        res.status(401).json({message: "Invalid credentials"})
      }
    } catch (err) {
      next(err);
    }
  })


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

  router.get('/logout', (req, res, next) => {
    if (req.session) {
      req.session.destroy(err => {
        if (err) {
          res.status(400).json({message: ""})
        } else {
          res.json({message: "logged out"})
        }
      })
    } else {
      res.json({message: "no session"})
    }
  })

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
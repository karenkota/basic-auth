
const express = require('express');

const router = express.Router();
const bcrypt = require("bcrypt");
const User = require("../models/user");
const bcryptSalt = 10;
const passport = require('passport');
const SlackStrategy = require('passport-slack').Strategy;

router.get('/signup', (req, res, next) => {
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {
  const { username } = req.body;
  const { password } = req.body;

  if (username === '' || password === '') {
    res.render('auth/signup', {
      errorMessage: 'Indicate a username and a password to sign up',
    });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      if (user !== null) {
        res.render('auth/signup', {
          errorMessage: 'The username already exists!',
        });
        return;
      }
      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      User.create({
        username,
        password: hashPass,
      })
        .then(() => {
          res.redirect('/');
        })
        .catch((error) => {
          console.log(error);
        });
    })
    .catch((error) => {
      next(error);
    });
});

router.get('/auth/slack', passport.authenticate('slack'));
router.get('/auth/slack/callback', passport.authenticate('slack', {
  successRedirect: '/secret',
  failureRedirect: '/',
}));

router.get('/login', (req, res, next) => {
  res.render('auth/login');
});

router.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, username and password to sign up.',
    });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      console.log(user);
      if (!user) {
        res.render('auth/login', {
          errorMessage: "The username doesn't exist.",
        });
        return;
      }
      if (bcrypt.compareSync(password, user.password)) {
        // Save the login in the session!
        req.session.currentUser = user;
        res.redirect('secret');
      } else {
        res.render('auth/login', {
          errorMessage: 'Incorrect password',
        });
      }
    })
    .catch((error) => {
      next(error);
    });
});
router.get('/logout', (req, res, next) => {
  req.session.destroy((err) => {
    // can't access session here
    res.redirect('/login');
  });
});



module.exports = router;

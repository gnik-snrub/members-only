const bcrypt = require('bcryptjs')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');

const { body, validationResult } = require('express-validator')

const User = require('./models/user')
const Message = require('./models/message')

const app = express();

const mongoose = require('mongoose')
mongoose.set('strictQuery', false)

require('dotenv').config()
const mongoDB = process.env.MONGO_URL

main().catch((err) => console.log(err))
async function main() {
  await mongoose.connect(mongoDB)
}

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({ secret: process.env.SESSION_SECRET, resave: true, saveUninitialized: true}))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

passport.use(
  new LocalStrategy(async (username, password, done) => {
    const user = await User.findOne({ username: username })
    if (!user) {
      return done(null, false, { message: 'Incorrect username' })
    }
    const match = await bcrypt.compare(password, user.password)
    if (!match) {
      return done(null, false, { message: 'Incorrect password' })
    }
    return done(null, user)
  })
)

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id)
  done(null, user)
})

app.use((req, res, next) => {
  res.locals.currentUser = req.user
  next()
})

app.get('/signup', (req, res) => {
  res.render('signup', { title: 'Sign up!' })
})
app.post('/signup', [
  body('first_name', 'First name must not be empty').trim().isLength({min: 1}),
  body('last_name', 'Last name must not be empty').trim().isLength({min: 1}),
  body('username', 'Username must not be empty').trim().isLength({min: 1}),
  body('password', 'Password must not be empty').trim().isLength({min: 1}),
  body('confirm').custom((value, { req })=> {
    if (!req.body.password) {
      return true
    }
    if (value !== req.body.password) {
      throw new Error('Passwords do not match')
    }
    return true
  }),
  async (req, res, next) => {
    const errors = validationResult(req)

    const user = {
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      username: req.body.username
    }
    if (!errors.isEmpty()) {
      res.render('signup', {
        title: 'Sign up!',
        errors: errors.array(),
        user
      })
      return
    } else {
      bcrypt.hash(req.body.password, 10, async(err, hashedPassword) => {
        const user = new User({
          first_name: req.body.first_name,
          last_name: req.body.last_name,
          username: req.body.username,
          password: hashedPassword,
          membershipStatus: false,
          admin: false,
        })
        await user.save()
        res.redirect('/')
      })
    }
  }
])

app.post('/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/'
  })
)

app.get('/logout', async(req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err)
    }
    res.redirect('/')
  })
})

app.get('/join_club', (req, res, next) => {
  res.render('join_club', {title: 'Join the club', status: req.user ? req.user.membershipStatus : false })
})
app.post('/join_club', [
  body('secret').custom((value, {req}) => {
    if (value === process.env.MEMBERSHIP_PASSWORD || value === process.env.ADMIN_PASSWORDD) {
      return true
    }
    throw new Error('Incorrect secret password')
  }),
  body('secret').custom((value, {req}) => {
    if (!req.user) {
      throw new Error('Must be logged in to join the club')
    }
    return true
  }),
  async(req, res, next) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      res.render('join_club', {
        title: 'Join the club',
        status: req.user ? req.user.membershipStatus : false,
        errors: errors.array()
      })
      return
    } else {
      if (req.body.secret === process.env.MEMBERSHIP_PASSWORD) {
        req.user.membershipStatus = true
        await User.findByIdAndUpdate(req.user.id, req.user)
        res.redirect('/')
      } else if (req.body.secret === process.env.ADMIN_PASSWORD) {
        req.user.admin = true
        await User.findByIdAndUpdate(req.user.id, req.user)
        res.redirect('/')
      }
    }
  }
])

app.post('/create_message', [
  body('message', 'Message cannot be empty').trim().isLength({min: 1}),
  async(req, res, next) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      const messages = await Message.find().populate('author').sort({timestamp: -1})
      res.render('index', { title: 'Members Only', user: req.user, messages, errors: errors.array() })
      return
    } else {
      const message = new Message({
        author: req.user,
        content: req.body.message,
        timestamp: new Date()
      })
      await message.save()
      res.redirect('/')
    }
  }
])

app.post('/delete', async(req, res, next) => {
  await Message.findByIdAndRemove(req.body.messageid)
  res.redirect('/')
})

app.get('/', async (req, res, next) => {
  const messages = await Message.find().populate('author').sort({timestamp: -1})
  res.render('index', { title: 'Members Only', user: req.user, messages })
})

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

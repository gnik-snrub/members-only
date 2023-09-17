const bcrypt = require('bcryptjs')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');

const User = require('./models/user')

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
  console.log(user)
  done(null, user)
})

app.use((req, res, next) => {
  res.locals.currentUser = req.user
  next()
})

app.get('/signup', (req, res) => {
  res.render('signup', { title: 'Sign up!' })
})
app.post('/signup', async (req, res, next) => {
  bcrypt.hash(req.body.password, 10, async(err, hashedPassword) => {
    const user = new User({
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      username: req.body.username,
      password: hashedPassword,
      membershipStatus: false,
    })
    await user.save()
    res.redirect('/')
  })
})

app.post('/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/'
  })
)

app.get('/', (req, res, next) => {
  res.render('index', { title: 'Members Only', user: req.user})
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

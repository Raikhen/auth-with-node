const csurf = require('csurf')
const helmet = require('helmet')
const bcrypt = require('bcryptjs')
const express = require('express')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
const sessions = require('client-sessions')

// Define function to check if user is logged in easily
const loginRequired = (req, res, next) => {
  if (!req.user) return res.redirect('/login')
  next()
}

// Connect to MongoDB
mongoose.connect('mongodb://localhost/auth', { useNewUrlParser: true })

// Just not to show an ugly warning in console
mongoose.set('useCreateIndex', true)

// Define Mongoose User schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
})

// Deine Mongoose User model
const User = mongoose.model('User', userSchema)

// Create server
const app = express()

// Set up template engine
app.set('view engine', 'pug')

// Add middleware to get JSON from POST requests
app.use(bodyParser.urlencoded({ extended: false }))

// More security!
app.use(helmet())

// Add middleware to handle sessions
app.use(sessions({
  cookieName: 'session',
  secret: 'kSFzKagRZ5bF',
  duration: 24 * 60 * 60 * 1000, // 1 day
  httpOnly: true,
  secure: true
}))

// Cross Site Request Forgery protection middleware
app.use(csurf())

// Add middleware to add user to requests
app.use((req, res, next) => {
  if (!(req.session && req.session.userId)) return next()

  User.findById(req.session.userId, (err, user) => {
    if (err) return next(err)
    if (!user) return next()

    user.password = undefined
    req.user = user
    res.locals.user = user

    next()
  })
})

// Index route
app.get('/', (req, res) => {
  res.render('index')
})

// Registration route
app.get('/register', (req, res) => {
  res.render('register', { csrfToken: req.csrfToken() })
})

// Login route
app.get('/login', (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() })
})

// Dashboard route
app.get('/dashboard', loginRequired, (req, res, next) => {
  const { session } = req
  if (!(session && session.userId)) return res.redirect('/login')

  User.findById(session.userId, (err, user) => {
    if (err) return next(err)
    if (!user) return res.redirect('/login')
    res.render('dashboard')
  })

  res.render('dashboard')
})

// Registration request handler
app.post('/register', (req, res) => {
  const password = bcrypt.hashSync(req.body.password, 14)
  const user = new User({ ...req.body, password })

  user.save((err) => {
    if (err) {
      let error = 'Error 729. Please try again.'
      if (err.code === 11000) error = 'Email already taken.'
      return res.render('register', { error })
    }

    req.session.userId = user.id
    res.redirect('/dashboard')
  })
})

// Login request handler
app.post('/login', (req, res) => {
  const { email, password } = req.body

  User.findOne({ email }, (err, user) => {
    if (err || !bcrypt.compareSync(password, user.password)) {
      return res.render('login', { error: 'Incorrect credentials.' })
    }

    req.session.userId = user._id
    res.redirect('/dashboard')
  })
})

// Run server on port 3000
app.listen(3000, () => {
  console.log('Server running!')
})

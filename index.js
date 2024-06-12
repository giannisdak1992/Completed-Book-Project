import express from 'express'
import bodyParser from 'body-parser'
import pg from 'pg'
import bcrypt from 'bcrypt'
import session from 'express-session'
import passport from 'passport'
import { Strategy } from 'passport-local'
import env from 'dotenv'

const app = express()
const port = 3000
const saltRounds = 10
env.config()

app.use(express.static('public'))

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false, //we are going to save it in our app
    saveUninitialized: true, //we actually store the unitialized sessions into our store
    cookie: {
      maxAge: 1000 * 60 * 60,
    },
  })
)

app.use(passport.initialize())
app.use(passport.session())

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DB,
  password: process.env.PG_PASS,
  port: process.env.PG_PORT,
})

db.connect()

let books

app.get('/', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM books ')
    books = result.rows
    res.render('index.ejs', { books: books })
  } catch (err) {
    console.log(err)
  }
})

app.get('/register', async (req, res) => {
  res.render('register.ejs')
})

app.get('/login', async (req, res) => {
  res.render('login.ejs')
})

app.get('/books', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM books ')
    books = result.rows
    if (req.isAuthenticated()) {
      //is the current use who's logged in the current session authenticated already
      res.render('isloginorregister.ejs', { books: books })
    } else {
      res.redirect('/login')
    }
  } catch (err) {
    console.log(err)
  }
})

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.log(err)
    } else {
      res.render('index.ejs', { books: books })
    }
  })
})
app.post('/register', async (req, res) => {
  const email = req.body.username
  const password = req.body.password

  try {
    //here i am storing the result in order to check it
    const checkResult = await db.query('SELECT * FROM users WHERE email = $1', [
      email,
    ])

    if (checkResult.rows.length > 0) {
      res.send('Email already exists. Try logging in.')
    } else {
      //password hashing
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log('Error hashing password:', err)
        } else {
          //here i am storing the result in order to print it
          const result = await db.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
            [email, hash]
          )
          const user = result.rows[0] //we can actually get hold of the new user through this result
          console.log(result)
          req.login(user, (err) => {
            //once we call req.login, this automatically authenticates our user
            console.log(err)
            res.redirect('/books')
          }) //we are going to pass the user that we are going to save to the session
        }
      })
    }
  } catch (err) {
    console.log(err)
  }
})

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/books',
    failureRedirect: '/login',
  })
)

// Route to render the edit page
app.get('/new', (req, res) => {
  res.render('modify.ejs', {
    heading: 'My Favorite book',
    submit: 'Post It!',
  })
})

//create new book
app.post('/add', async (req, res) => {
  const title = req.body.title
  const author = req.body.author
  const coverId = req.body.cover_id
  const rating = req.body.rating

  try {
    await db.query(
      'INSERT INTO books (title, author,cover_id, rating) VALUES ($1,$2, $3, $4)',
      [title, author, coverId, rating]
    )
  } catch (err) {
    console.log(err)
  }
  res.redirect('/books')
})

// Partially update a post
app.post('/edit', async (req, res) => {
  const rating = req.body.rating
  const id = req.body.updatedBookId

  try {
    await db.query('UPDATE books SET rating = $1 WHERE book_id = $2', [
      rating,
      id,
    ])
  } catch (err) {
    console.log(err)
  }

  res.redirect('/books')
})

app.post('/delete', async (req, res) => {
  const id = req.body.deleteBookId
  try {
    await db.query('DELETE FROM books WHERE book_id = $1', [id])
    res.redirect('/books')
  } catch (err) {
    console.log(err)
  }
})

passport.use(
  new Strategy(async function verify(username, password, cb) {
    //IT TAKES AUTOMATICALLY THE USERNAME AND PASSWORD FROM THE FORM
    try {
      const result = await db.query('SELECT * FROM  users WHERE email = $1', [
        username,
      ])

      if (result.rows.length > 0) {
        const user = result.rows[0]
        const storedHashedPassword = user.password
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err)
          } else {
            if (result) {
              return cb(null, user)
            } else {
              return cb(null, false) //this tells us that when we check is Authenticated to false
            }
          }
        })
      } else {
        return cb('User not found')
      }
    } catch (err) {
      return cb(err)
    }
  })
) //it is trying to validate whether if a user already has the right password if the email already exists in the database (or whatever it is in the login route)
//it get triggered wherever we try to authenticate a user

passport.serializeUser((user, cb) => {
  //we can save the data of the user who's logged in to local storage
  cb(null, user)
})

passport.deserializeUser((user, cb) => {
  //it saves the user's information such as their ID, their email, to the local session
  cb(null, user)
})

app.listen(port, () => {
  console.log(`Backend server is running on http://localhost:${port}`)
})

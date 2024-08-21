require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const MongoStore = require("connect-mongo");

const app = express();
const port = 3000;

const saltRounds = 11;

// Mongoose connect and start server
mongoose
  .connect("mongodb://localhost:27017/fetDB")
  .then(() => {
    console.log("Connected To DB");
    app.listen(port, () => {
      console.log(`Server Started On Port ${port}`);
    });
  })
  .catch((err) => console.error("Error connecting to DB", err));

// Middleware
app.use(
  session({
    secret: "hello world",
    saveUninitialized: false,
    resave: false,
    store: MongoStore.create({ mongoUrl: "mongodb://localhost:27017/fetDB" }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 1 day
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(passport.initialize());
app.use(passport.session());

// Schemas and Models
const expenseSchema = new mongoose.Schema({
  name: { type: String, required: true, minLength: 3 },
  amount: { type: Number, required: true },
  category: { type: String, required: true },
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, minLength: 3 },
  email: { type: String, required: true, minLength: 8, unique: true },
  password: { type: String, minLength: 8 },
  googleId: { type: String, unique: true },
});

const Expense = mongoose.model("expense", expenseSchema);
const User = mongoose.model("user", userSchema);

// Passport Local Strategy
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) {
          return done(null, false, { message: "User Not Found" });
        }
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
          return done(null, false, { message: "Incorrect Password" });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/success",
    },
    async (token, tokenSecret, profile, done) => {
      try {
        const user = await User.findOne({ googleId: profile.id });
        if (user) {
          return done(null, user);
        } else {
          const newUser = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id,
          });
          await newUser.save();
          return done(null, newUser);
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Routes
app.get("/auth/signup", (req, res) => {
  res.render("signup.ejs");
});

app.get("/auth/login", (req, res) => {
  res.render("login.ejs");
});

app.get(
  "/auth/google/",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/success",
  passport.authenticate("google", {
    failureRedirect: "/auth/login",
  }),
  (req, res) => {
    res.redirect("/");
  }
);

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/auth/login");
  });
});

app.get("/:category?", (req, res) => {
  if (req.isAuthenticated()) {
    const category = req.params.category;
    const filter = category ? { category } : {};

    Expense.find(filter)
      .then((foundExpenses) => {
        res.render("index", {
          data: foundExpenses.length > 0 ? foundExpenses : "No expenses found",
        });
      })
      .catch((err) => console.error(err));
  } else {
    res.redirect("/auth/login");
  }
});

app.post("/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.redirect("/auth/login");
    }

    const hash = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ name, email, password: hash });
    await newUser.save();
    req.login(newUser, (err) => {
      if (err) return console.error("Error logging in:", err);
      res.redirect("/");
    });
  } catch (err) {
    console.error(err);
  }
});

app.post(
  "/auth/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/auth/login",
  })
);

app.post("/", (req, res) => {
  const { name, amount, category } = req.body;
  const expense = new Expense({ name, amount, category });

  expense
    .save()
    .then((savedExpense) => {
      res.redirect("/");
    })
    .catch((err) => console.error(err));
});

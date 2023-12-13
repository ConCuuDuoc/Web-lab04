const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require("bcrypt");
const User = require("../model/user");
require('dotenv').config();

async function initialize(passport, getUserByEmail, getUserById) {

  const authenticateUsers = async (email, password, done) => {
    try {
      const user = await getUserByEmail(email);
      if (!user) {
        return done(null, false, { message: "No user found with that email" });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Password Incorrect" });
      }
    } catch (error) {
      console.log(error.message);
      return done(error);
    }
  };

  const authenticateGoogleUser = async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await getUserByEmail(profile.emails[0].value);
      if (user) {
        return done(null, user);
      } else {
        const user = new User({
          name: profile.displayName,
          email: profile.emails[0].value,
        });
        await user.save();
        return done(null, user);
      }
    } catch (error) {
      console.error(error);
      return done(error);
    }
  }

  passport.use(
    "local",
    new LocalStrategy({ usernameField: "email" }, authenticateUsers)
  );

  passport.use(
    "google",
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
      },
      authenticateGoogleUser
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    getUserById(id)
      .then((user) => done(null, user))
      .catch((error) => done(error));
  });

}



module.exports = initialize;

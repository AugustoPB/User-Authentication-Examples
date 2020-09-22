require('dotenv').config({ path: './config/.env'})
const LocalStrategy = require('passport-local').Strategy
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const User = require('../models/User')
module.exports = function(passport) {
    passport.use(
        new LocalStrategy({usernameField: 'email'}, (email, password, done) => {
            // Match user
            User.findOne({email: email})
            .then(user => {
                if(!user) return done(null, false, {message: 'This email is not registered.'})

                if(user.password == undefined && user.sub != undefined) done(null, false, {message: 'Please login with your Google account.'})
                else {
                //Match password
                bcrypt.compare(password, user.password, (err, isMatch) => {
                    if(err) throw err
                    if(isMatch) return done(null, user)
                    else done(null, false, {message: 'Wrong password'})
                })
                }
            })
            .catch(err => console.log(err))
        })
    )

    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/users/auth/google/callback"
      },
      function(accessToken, refreshToken, profile, done) {
        const {name, email, sub} = profile._json
        User.findOne({email: email})
        .then(user => {
            if(!user) {
                const newUser = new User({
                    sub,
                    name,
                    email,
                })
                newUser.save()
                .then(user => {
                    return done(null, user)
                })
                .catch(err => console.log(err))
            }
            else return done(null, user)
        })
        .catch(err => console.log(err))
      }
    ))

    passport.serializeUser((user, done) => {
        done(null, user.id)
    })

    passport.deserializeUser((id, done) => {
        User.findById(id, (err, user) => {
            done(err, user)
        })
    })
}
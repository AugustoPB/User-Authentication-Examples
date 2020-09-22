const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const passport = require('passport')

const User = require('../models/User')

router.get('/login', (req, res) => res.render('login'))

router.get('/register', (req, res) => res.render('register'))

router.post('/register', (req, res) => {
    const {name, email, password, password2} = req.body
    let errors = []

    // Validate inputs
    if(!name || !email || !password || !password2) {
        errors.push({msg: 'Please fill all fields.'})
    }
    if(password !== password2) {
        errors.push({msg: 'Passwords do not match.'})
    }
    if(password.length < 6) {
        errors.push({msg: 'Passwords must have at least 6 characters.'})
    }
    if(errors.length > 0){
        res.render('register', {
            errors,
            name,
            email
        })
    }
    else {
        // Validation passed
        User.findOne({email: email})
        .then(user => {
            if(user) {
                // User exists
                errors.push({msg: 'Email already registered.'})
                res.render('register', {
                    errors,
                    name,
                    email
                })
            }
            else {
                const newUser = new User({
                    name,
                    email,
                    password
                })

                // Hash Password
                bcrypt.genSalt(10, (err, salt) => 
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err

                        newUser.password = hash
                        newUser.save()
                        .then(user => {
                            req.flash('success_msg', 'You are now registered. Please log in.')
                            res.redirect('/users/login')
                        })
                        .catch(err => console.log(err))
                }))
            }
        })
        .catch(err => console.log(err))
    }
})

router.post('/login', 
    passport.authenticate('local', {
        failureRedirect: '/users/login',
        failureFlash: true
    }), (req, res) => {
        res.redirect('/dashboard')
    })

router.get('/login/google', passport.authenticate('google', { scope : ['profile', 'email'] }))

router.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/users/login',
    failureFlash: true
    }),
  function(req, res) {
    // Successful authentication, redirect success.
    res.redirect('/dashboard')
})

router.get('/logout', (req, res) => {
    req.logout()
    req.flash('success_msg', 'You are now logged out')
    res.redirect('/users/login')
})

module.exports = router
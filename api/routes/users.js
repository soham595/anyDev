const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('../models/user');
const Profile = require('../models/profile');
const jwt = require('jsonwebtoken');
const checkAuth = require('../middleware/check-auth');

router.post('/signup', (req, res, next) => {
    User.find({email: req.body.email})
        .exec()
        .then(user => {
            if (user.length >= 1) {
                return res.status(409).json({
                    message: 'Mail exists'
                })
            } else {
                bcrypt.hash(req.body.password, 10, (err, hash) => {
                    if (err) {
                        return res.status(500).json({
                            error: err
                        });
                    } else {
                        const user = new User({
                            _id: new mongoose.Types.ObjectId(),
                            email: req.body.email,
                            password: hash
                        });
                        user.save()
                            .then(result => {
                                console.log(result);
                                res.status(201).json({
                                    message: 'User Created',
                                    createdUser: {
                                        email: result.email,
                                        _id: result._id,
                                    }
                                });

                            })
                            .catch(err => {
                                console.log(err);
                                res.status(500).json({
                                    error: err
                                })
                            });
                    }
                });
            }
        });
});

router.post('/login', (req, res, next) => {
    User.find({ email: req.body.email })
        .exec()
        .then(user => {
            if (user.length < 1) {
                return res.status(401).json({
                    message: 'Auth failed'
                });
            }
            bcrypt.compare(req.body.password, user[0].password, (err, result) => {
                if (err) {
                    return res.status(401).json({
                        message: 'Auth failed'
                    });
                }
                if (result) {
                    const token = jwt.sign(
                        {
                            email: user[0].email,
                            userId: user[0]._id
                        },
                        process.env.JWT_KEY,
                        {
                            expiresIn: "1h"
                        }
                    );
                    return res.status(200).json({
                        message: 'Auth successful',
                        token: token,
                        createdUser: {
                            email: user[0].email,
                            _id: user[0]._id
                        },
                    });
                }
                res.status(401).json({
                    message: 'Auth failed'
                });
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error: err
            });
        });
});

router.delete('/:userId', (req, res, next) => {
    const id = req.params.userId;
    User.remove({_id: id})
        .exec()
        .then(result => {
            res.status(200).json({
                message: 'User deleted',
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error: err
            });
        });
});

router.post('/profile/:userId', checkAuth, (req, res, next) => {
    
    var query = {};
    var update = {
        name: req.body.name,
        age: req.body.age,
        user: req.body.user,
        education: req.body.education,
        location: req.body.location,
        phone: req.body.phone
    };
    var options = {upsert: true, new: true,};
    Profile.findOneAndUpdate(query, update, options)
        .exec()
        .then( result => {
            console.log(result);
            res.status(201).json(result);
        })
        .catch( err => {
            console.log(err);
            res.status(500).json({error: err});
        })
});

module.exports = router;
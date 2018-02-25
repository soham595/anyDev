const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const users = require('./users');
const products = require('./products');

mongoose.connect('mongodb://localhost:27017/anystore');


app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

app.use('/users', users);
app.use('/products', products);


module.exports = app;
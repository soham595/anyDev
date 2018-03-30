const mongoose = require('mongoose');

const followSchema = mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    following: {type: mongoose.Schema.Types.ObjectId, ref: 'Profile', required: true}
});

module.exports = mongoose.model('Follow', followSchema);
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({ 
    email: {
        type: String,
        required: [true, 'Please provide an email'],
        unique: true
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: 6,
        select: false
    }, 
    roles: {
        type: [String],
        default: ["User"]
    },
    firstNaùe: {
        type: String,
        required: [true, 'Please provide a first name']
    },
    lastName: {
        type: String,
        required: [true, 'Please provide a last name']
    },
    active : {
        type: Boolean,
        default: true
    }
},{timestamps: true});

module.exports = mongoose.model('User', UserSchema);
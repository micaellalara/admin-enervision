const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: [/.+@.+\..+/, 'Please enter a valid email address'],
    },
    password: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
        unique: true,
    },
    kwhRate: {
        type: Number,
        required: true,
    },
    picture: {
        type: String,
        required: false
    },
    communityGuidelinesAccepted: {
        type: Boolean,
        default: false, 
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'reporter'],
        required: true,
    },
    status: {
        type: String,
        enum: ['active', 'banned', 'deleted'],
        default: 'active',
    },
    userprofileId: {
        type: Schema.Types.ObjectId,
        ref: 'UserProfile'
    },
    postCount: {
        type: Number,
        default: 0,
    },
    banReason: {
        type: String
    },
    banDate: {
        type: Date
    },
    appliances: [{
        type: Schema.Types.ObjectId,
        ref: 'Appliance'
    }],
    posts: [{
        type: Schema.Types.ObjectId,
        ref: 'Post'
    }],
    energyDiary: [{
        type: Schema.Types.ObjectId,
        ref: 'EnergyDiary'
    }],
    deletedAt: {
        type: Date,
        default: null
    },
    communityGuidelinesAccepted: {
        type: Boolean,
        default: false, 
      },

}, { timestamps: true });

module.exports = mongoose.model("User", userSchema, 'users');

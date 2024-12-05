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
        type: String // New field for ban reason
    },
    banDate: {
        type: Date // New field for ban date
    },
    appliances: [{
        type: Schema.Types.ObjectId,
        ref: 'Appliance' // New field for appliances reference
    }],
    posts: [{
        type: Schema.Types.ObjectId,
        ref: 'Post' // New field for posts reference
    }],
    energyDiary: [{
        type: Schema.Types.ObjectId,
        ref: 'EnergyDiary' // New field for energy diary reference
    }],
    deletedAt: {
        type: Date,
        default: null // New field for soft delete
    }

}, { timestamps: true });

module.exports = mongoose.model("User", userSchema, 'users');

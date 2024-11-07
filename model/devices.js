const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const deviceInfo = new Schema({
    deviceName: { 
        type: String, 
        required: true, 
        trim: true 
    },
    description: { 
        type: String 
    },
    capacity: { 
        type: String, 
        required: true, 
        trim: true 
    },
    material: { 
        type: String, 
        required: true 
    },
    purchasePrice: { 
        type: Number, 
        required: true 
    },
    powerConsumption: { 
        type: String, 
        required: true 
    },
    costPerHour: { 
        type: Number, 
        required: true 
    },
    monthlyCost: { 
        type: String, 
        required: true 
    },
    applianceCategory: {
        type: String,
        enum: [
            'Lighting',
            'Entertainment',
            'Cooking',
            'Cooling',
            'Laundry'
        ],
        required: true, 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date, 
        default: null 
    },
    deletedAt: { 
        type: Date, 
        default: null 
    },
});

deviceInfo.index({ deviceName: 1 });

module.exports = mongoose.model('Device', deviceInfo, 'deviceInfo');

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const compareApplianceSchema = new Schema({
    compareApplianceName: {
        type: String,
        required: true,
        unique: true
    },
    costPerHour: {
        type: Number,
        required: true,
        min: 0
    },
    monthlyCost: {
        type: Number,
        required: true,
        min: 0
    },
    carbonEmission: {
        type: Number,
        required: true,
        min: 0
    }
});

module.exports = mongoose.model('Compare', compareApplianceSchema);
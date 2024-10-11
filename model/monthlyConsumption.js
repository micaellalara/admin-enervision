const mongoose = require('mongoose');
const Schema = mongoose.Schema;
//
//const monthlyConsumptionSchema = new Schema({
//  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
//  applianceId: { type: Schema.Types.ObjectId, ref: 'Appliance', required: true },
//  day: { type: Number, required: true },
//  month: { type: Number, required: true },
//  year: { type: Number, required: true },
//  monthlyWattage: { type: Number },
//  monthlyCost: { type: Number }
//});
//
//monthlyConsumptionSchema.index({ userId: 1, month: 1, year: 1 });
//const MonthlyConsumption = mongoose.model('MonthlyConsumption', monthlyConsumptionSchema);
//module.exports = MonthlyConsumption;


const monthlyConsumptionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    month: {
        type: String,
        required: true
    },
    totalMonthlyConsumption: {
        type: Number,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const MonthlyConsumption = mongoose.model('MonthlyConsumption', monthlyConsumptionSchema);

module.exports = MonthlyConsumption;


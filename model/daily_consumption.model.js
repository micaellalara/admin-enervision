const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const dailyConsumptionSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  applianceId: { type: Schema.Types.ObjectId, ref: 'Appliance', required: true },
  date: { type: Date, required: true }, // Use a Date type for better handling
  dailyWattage: { type: Number, required: true },
  dailyCost: { type: Number, required: true }
});

dailyConsumptionSchema.index({ userId: 1, applianceId: 1, date: 1 });

const DailyConsumption = mongoose.model('DailyConsumption', dailyConsumptionSchema);
module.exports = DailyConsumption;

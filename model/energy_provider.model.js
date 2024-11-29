const mongoose = require('mongoose');

const EnergyProviderSchema = new mongoose.Schema({
  providerName: { type: String, required: true },
  ratePerKwh: { type: Number, required: true },
});

module.exports = mongoose.model('EnergyProvider', EnergyProviderSchema);
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const energyTips = new Schema({
  energyTipsTitle: {
    type: String,
    required: true
  },
  energyTipsText: {
    type: String,
    required: true
  },
  uploadPhoto: String,
});

const EnergyTips = mongoose.model('EnergyTips', energyTipsSchema);

module.exports = EnergyTips;

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const installationSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  installationDate: { type: Date, required: true },
  installationLocation: { type: String, required: true },
  installationNotes: { type: String, required: false },
  deviceType: { type: String, required: true }
}, { timestamps: true });

const EnerVisionInstallation = mongoose.model('EnerVisionInstallation', installationSchema);

module.exports = EnerVisionInstallation;

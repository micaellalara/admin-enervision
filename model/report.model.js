const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const reportSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  reporterId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  reportReason: { type: String },
  reportDescription: { type: String },
  reportStatus: {
    type: String,
    enum: ['Reviewed', 'Banned', 'Unbanned', 'Unreviewed'],
    default: 'Unreviewed'
  }
}, { timestamps: true });

const Report = mongoose.model('Report', reportSchema);

module.exports = Report;

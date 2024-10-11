const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const applianceSchema = new Schema({
    applianceName: { type: String, required: true, trim: true },
    wattage: { type: Number, required: true },
    usagePatternPerDay: { type: Number, required: true },
    usagePatternPerWeek: { type: Number, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    applianceCategory: {
        type: String,
        enum: [
            'Personal Devices',
            'Kitchen Appliances',
            'Cleaning & Laundry Appliances',
            'Personal Care Appliances',
            'Home Media and Office Appliances',
            'Climate and Lighting Control Appliances'
        ],
        default: 'Personal Devices',
    },
    deletedAt: { type: Date, default: null },
}, { timestamps: true });

applianceSchema.index({ userId: 1 });

module.exports = mongoose.model('Appliance', applianceSchema);


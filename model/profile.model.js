const mongoose = require('mongoose');
const { Schema } = mongoose;

const userProfileSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  gender: { type: String, required: true },
  occupation: { type: String, required: true },
  birthDate: { type: Date, required: true },
  energyInterest: { type: String },
  mobileNumber: {
    type: String,
    match: [/^\d{10}$/, 'Please enter a valid mobile number'],
  },
  avatar: { type: String },
  registrationDate: { type: Date, required: true, default: Date.now },
  isRegistered: { type: Boolean, required: true, default: false },
  address: {
    countryLine: {
      type: String,
      enum: ['USA', 'Canada', 'UK', 'Australia', 'Philippines'],
      required: true,
    },
    cityLine: { type: String, required: true },
    streetLine: { type: String, required: true },
  },
  deletedAt: { type: Date, default: null },
}, { timestamps: true });

userProfileSchema.methods.getAge = function() {
  const today = new Date();
  const birthDate = new Date(this.birthDate);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDifference = today.getMonth() - birthDate.getMonth();
  if (monthDifference < 0 || (monthDifference === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age;
};

const UserProfile = mongoose.model('UserProfile', userProfileSchema);
module.exports = UserProfile;

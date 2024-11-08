
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid'); 

const messageSchema = new mongoose.Schema({
    sender: { type: String, required: true },  
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
    conversationId: { type: String, default: uuidv4, unique: true }, 
    userId: { type: String, required: true, ref: 'User' }, 
    created_at: { type: Date, default: Date.now }, 
    updated_at: { type: Date, default: Date.now },
    messages: [messageSchema], 
    adminReplies: [messageSchema] 
});

chatSchema.pre('save', function(next) {
    this.updated_at = Date.now();
    next();
});

// Export the model
const Chat = mongoose.model('Chat', chatSchema);
module.exports = Chat;
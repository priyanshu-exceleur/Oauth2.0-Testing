const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: String,
    password: String,  // You should hash passwords in a real-world app
});

const ClientSchema = new mongoose.Schema({
    clientId: String,
    clientSecret: String,
    redirectUris: [String],
    grants: [String],
});

const AuthCodeSchema = new mongoose.Schema({
    code: String,
    clientId: String,
    userId: mongoose.Schema.Types.ObjectId,
    redirectUri: String,
    expiresAt: Date,
});

const User = mongoose.model('User', UserSchema);
const Client = mongoose.model('Client', ClientSchema);
const AuthCode = mongoose.model('AuthCode', AuthCodeSchema);

module.exports = { User, Client, AuthCode };

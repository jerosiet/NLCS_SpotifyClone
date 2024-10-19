const mongoose = require("mongoose");
const user = new mongoose.Schema({
    tenNguoiDung:{
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    sdtNguoiDung:{
        type: String,
        required: true,
    },
    emailNguoiDung: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
    },
    likedSongs: {
        type: String,
        default: "",
    },
    likedPlaylist: {
        type: String,
        default: "",
    },
    subscribedArtists: {
        type: String,
        default: "",
    },
})

const UserModel = mongoose.model("User", user);

module.exports = UserModel;
const mongoose = require("mongoose");
const song = new mongoose.Schema({
    tenBaiHat:{
        type: String,
        required: true,
    },
    cover: {
        type: String,
        required: true,
    },
    track: {
        type: String,
        required: true,
    },
    NgayDang: {
        type: Date,
        default: Date.now,
    },
    artist: {
        type: mongoose.Types.ObjectId,
        ref: "user",
    }
})

const SongModel = mongoose.model("Song", song);

module.exports = SongModel;
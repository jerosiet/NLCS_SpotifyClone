const mongoose = require("mongoose");
const playlist = new mongoose.Schema({
    tenDanhSachPhat:{
        type: String,
        required: true,
    },
    thumbnail: {
        type: String,
        required: true,
    },
    owner: {
        type: mongoose.Types.ObjectId,
        ref: "user",
    }, 
    songs: [
        {
            type: mongoose.Types.ObjectId,
            ref: "song",
        },
    ],
    collaborators: [
        {
            type: mongoose.Types.ObjectId,
            ref: "user",
        },
    ],
    isFavorite: {
        type: Boolean,
        default: false,
    }
});

const PlaylistModel = mongoose.model("Playlist", playlist);

module.exports = PlaylistModel;
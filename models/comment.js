const mongoose = require("mongoose");
const comment = new mongoose.Schema({
    noiDung:{
        type: String,
        required: true,
    },
    NgayDang: {
        type: Date,
        default: Date.now,
        required: true,
    },
    user: {
        type: mongoose.Types.ObjectId,
        ref: "user",
        required: true,
    },
    song: {
        type: mongoose.Types.ObjectId,
        ref: "song",
        required: true,
    },
});

const CommentModel = mongoose.model("Comment", comment);

module.exports = CommentModel;
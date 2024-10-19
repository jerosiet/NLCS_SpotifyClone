const express = require("express");
const router = express.Router();
const passport = require("passport");
const Comment = require("../models/comment");

router.post("/add/comment", passport.authenticate("jwt", { session: false }), async (req, res) => {
    const { noiDung, songId } = req.body;
    const currentUser = req.user;

    if (!noiDung || !songId) {
        return res.status(400).json({ message: "Content and song ID are required" });
    }

    const newComment = new Comment({
        noiDung,
        user: currentUser._id,
        song: songId,
    });

    await newComment.save();
    return res.status(200).json({ message: "Comment added", comment: newComment });
});

module.exports = router;

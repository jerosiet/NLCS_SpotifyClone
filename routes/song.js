const express = require("express");
const router = express.Router();
const passport = require("passport");
const Song = require("../models/song");
const User = require("../models/user");

router.post("/create", passport.authenticate("jwt", {session: false}), async (req, res) => {
    const {tenBaiHat, cover, track} = req.body;
    if (!tenBaiHat || !cover || !track) {
        return res.status(301).json({err: "Insufficient details to create song."})
    }
    const artist = req.user._id;
    const songDetails = {tenBaiHat, cover, track, artist};
    const createdSong = await Song.create(songDetails);
    return res.status(200).json(createdSong);
});

router.get("/get/mysongs", passport.authenticate("jwt", {session: false}), async (req, res) => {
    const currentUser = req.user;
    const songs = await Song.find({artist: currentUser});
    return res.status(200).json({data:songs});
});

router.get("/get/artist/:artistId", passport.authenticate("jwt", {session: false}), async (req, res) => {
    console.log("Route /get/artist/:artistId hit!");
    const {artistId} = req.params;
    const artist = await User.findOne({_id: artistId});
    if(!artist) {
        return res.status(404).json({err:"Artist does not exists"});
    }
    const songs = await Song.find({artist:artistId});
    return res.status(200).json({data: songs});
});

router.get("/get/songname/:tenBaiHat", passport.authenticate("jwt", {session: false}), async (req,res) => {
    const {tenBaiHat} = req.params;
    const songs = await Song.find({tenBaiHat: tenBaiHat});
    return res.status(200).json({data: songs});
});

module.exports = router;
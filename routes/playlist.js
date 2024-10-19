const express = require("express");
const router = express.Router();
const passport = require("passport");
const Song = require("../models/song");
const User = require("../models/user");
const Playlist = require("../models/playlist");

router.post("/create", passport.authenticate("jwt", {session: false}), async (req,res) => {
    const currentUser = req.user;
    const {tenDanhSachPhat, thumbnail, songs} = req.body;
    if (!tenDanhSachPhat || !thumbnail || !songs) {
        return res.status(301).json({err: "Insufficient Data"});
    }
    const playlistData = { tenDanhSachPhat, thumbnail, songs, owner: currentUser._id, collaborators: [],        
    };
    const playlist = await Playlist.create(playlistData);
    return res.status(200).json(playlist);
})

router.get("/get/playlist/:playlistId", passport.authenticate("jwt", {session: false}), async (req,res) => {
    const playlistId = req.params.playlistId;
    const playlist = await Playlist.findOne({_id: playlistId});
    if(!playlist){
        return res.status(304).json({err: "Invalid ID"});
    }
    return res.status(200).json({playlist});
});

 router.get("/get/artist/:artistId",passport.authenticate("jwt", {session: false}), async (req,res) => {
    const artistId = req.params.artistId;
    const artist = await User.findOne({_id: artistId});
    if(!artist){
        return res.status(304).json({err: "Invalid Artist ID"});
    }
    const playlists = await Playlist.find({owner:artistId})
    return res.status(200).json({data:playlists});
});

router.post("/add/song", passport.authenticate("jwt", {session: false}), async (req,res) => {
    const currentUser = req.user;
    const {playlistId, songId} = req.body;
    const playlist = await Playlist.findOne({_id: playlistId});
    if(!playlist) {
        return res.status(304).json({err: "Playlist does not exist"});
    }
    if(!playlist.owner.equals(currentUser._id) && !playlist.collaborators.includes(currentUser._id)) {
        return res.status(400).json({err: "Not allowed"});
    }
    const song = await Song.findOne({_id:songId});
    if(!song){
        return res.status(304).json({err: "Song does not exist"});
    }
    playlist.songs.push(songId);
    await playlist.save();
    return res.status(200).json(playlist);
});

router.post("/favorite", passport.authenticate("jwt", { session: false }), async (req, res) => {
    const currentUser = req.user;
    const { songId } = req.body;

    const song = await Song.findById(songId);
    if (!song) {
        return res.status(404).json({ message: "Song not found" });
    }

    let favoritePlaylist = await Playlist.findOne({ owner: currentUser._id, isFavorite: true });

    if (!favoritePlaylist) {
        favoritePlaylist = new Playlist({
            tenDanhSachPhat: "Yêu thích",
            thumbnail: "default_thumbnail_url", 
            songs: [],
            owner: currentUser._id,
            isFavorite: true,
        });
    }

    if (favoritePlaylist.songs.includes(songId)) {
        return res.status(400).json({ message: "Song already in favorite playlist" });
    }

    favoritePlaylist.songs.push(songId);
    await favoritePlaylist.save();

    return res.status(200).json({ message: "Song added to favorite playlist", playlist: favoritePlaylist });
});


router.get("/favorite", passport.authenticate("jwt", { session: false }), async (req, res) => {
    const currentUser = req.user;
    
    const favoritePlaylist = await Playlist.findOne({ owner: currentUser._id, isFavorite: true });
    
    if (!favoritePlaylist) {
        return res.status(404).json({ message: "Favorite playlist not found" });
    }

    return res.status(200).json({ playlist: favoritePlaylist });
});

module.exports = router; 
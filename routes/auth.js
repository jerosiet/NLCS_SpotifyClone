const express = require("express");
const router = express.Router();
const User = require("../models/user");
const bcrypt = require("bcrypt");
const {getToken} = require("../utils/helpers")

router.post("/register", async (req,res) => {
    const {emailNguoiDung, password, tenNguoiDung, username, sdtNguoiDung} = req.body;
    const user = await User.findOne({emailNguoiDung: emailNguoiDung});
    if (user) {
        return res.status(403).json({error:"A user with this email already exists"});
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUserData = {emailNguoiDung, password: hashedPassword, tenNguoiDung, username, sdtNguoiDung};
    const newUser = await User.create(newUserData);
    const token = await getToken(emailNguoiDung, newUser);
    const userToReturn = { ...newUser.toJSON(), token};
    delete userToReturn.password;
    return res.status(200).json(userToReturn);
});

router.post("/login", async (req, res) => {
    const {emailNguoiDung, password} = req.body;
    if (!emailNguoiDung || !password) {
        return res.status(400).json({ err: "Missing email or password" });
    }
    const user = await User.findOne({emailNguoiDung});
    if(!user){
        return res.status(403).json({err: "Invalid credentials"});
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if(!isPasswordValid){
        return res.status(403).json({err: "Invalid credentials"});
    } 
    const token = await getToken(user.emailNguoiDung, user);
    const userToReturn = { ...user.toJSON(), token};
    delete userToReturn.password;
    return res.status(200).json(userToReturn);
});

module.exports = router;
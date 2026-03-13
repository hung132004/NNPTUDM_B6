const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const privateKey = fs.readFileSync("private.key");


// LOGIN
exports.login = async (req, res) => {

    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
        return res.status(400).json({ message: "User không tồn tại" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        return res.status(400).json({ message: "Sai mật khẩu" });
    }

    const token = jwt.sign(
        { id: user._id, username: user.username },
        privateKey,
        {
            algorithm: "RS256",
            expiresIn: "1h"
        }
    );

    res.json({
        token
    });
};



// API /me
exports.me = async (req, res) => {

    const user = await User.findById(req.user.id).select("-password");

    res.json(user);
};



// CHANGE PASSWORD
exports.changePassword = async (req, res) => {

    try {

        const userId = req.user.id;

        const { oldPassword, newPassword } = req.body;

        if (!oldPassword || !newPassword) {
            return res.status(400).json({
                message: "Thiếu dữ liệu"
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                message: "Mật khẩu mới phải >= 6 ký tự"
            });
        }

        const user = await User.findById(userId);

        const match = await bcrypt.compare(oldPassword, user.password);

        if (!match) {
            return res.status(400).json({
                message: "Old password không đúng"
            });
        }

        const hash = await bcrypt.hash(newPassword, 10);

        user.password = hash;

        await user.save();

        res.json({
            message: "Đổi mật khẩu thành công"
        });

    } catch (err) {

        res.status(500).json(err);
    }
};
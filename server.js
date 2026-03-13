const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const app = express();

app.use(express.json());

const privateKey = fs.readFileSync("private.key");
const publicKey = fs.readFileSync("public.key");


// user giả
let user = {
    id: 1,
    username: "admin",
    password: bcrypt.hashSync("123456", 10),
    email: "admin@gmail.com",
    fullName: "Admin"
};


// middleware auth
function authMiddleware(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: "Không có token" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, publicKey, { algorithms: ["RS256"] }, (err, decoded) => {

        if (err) {
            return res.status(401).json({ message: "Token không hợp lệ" });
        }

        req.user = decoded;

        next();
    });
}


// LOGIN
app.post("/login", async (req, res) => {

    const { username, password } = req.body;

    if (username !== user.username) {
        return res.status(400).json({ message: "Sai username" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        return res.status(400).json({ message: "Sai mật khẩu" });
    }

    const token = jwt.sign(
        { id: user.id, username: user.username },
        privateKey,
        {
            algorithm: "RS256",
            expiresIn: "1h"
        }
    );

    res.json({ token });
});


// API /me
app.get("/me", authMiddleware, (req, res) => {

    res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.fullName
    });
});


// CHANGE PASSWORD
app.post("/change-password", authMiddleware, async (req, res) => {

    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ message: "Thiếu dữ liệu" });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({
            message: "Mật khẩu mới phải >= 6 ký tự"
        });
    }

    const match = await bcrypt.compare(oldPassword, user.password);

    if (!match) {
        return res.status(400).json({
            message: "Old password không đúng"
        });
    }

    const hash = await bcrypt.hash(newPassword, 10);

    user.password = hash;

    res.json({
        message: "Đổi mật khẩu thành công"
    });

});


app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
});
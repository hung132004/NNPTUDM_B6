const jwt = require("jsonwebtoken");
const fs = require("fs");

const publicKey = fs.readFileSync("public.key");

module.exports = (req, res, next) => {

    const authHeader = req.headers["authorization"];

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
};
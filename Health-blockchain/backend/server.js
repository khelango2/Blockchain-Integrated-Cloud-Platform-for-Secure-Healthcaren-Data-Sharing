const express = require("express");
const fs = require("fs");
const multer = require("multer");
const { encrypt, decrypt, hash } = require("./cryptoUtil");

const app = express();
const upload = multer();

if (!fs.existsSync("storage")) {
    fs.mkdirSync("storage");
}

app.post("/upload", upload.single("file"), (req, res) => {
    const encrypted = encrypt(req.file.buffer);
    const fileHash = hash(encrypted);

    fs.writeFileSync(`storage/${fileHash}.enc`, encrypted);

    res.json({
        message: "File encrypted & stored",
        hash: fileHash
    });
});

app.get("/download/:hash", (req, res) => {
    const encrypted = fs.readFileSync(`storage/${req.params.hash}.enc`);
    const decrypted = decrypt(encrypted);
    res.send(decrypted);
});

app.listen(3000, () => {
    console.log(" Backend running at http://localhost:3000");
});

const crypto = require("crypto");
const algorithm = "aes-256-cbc";
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(buffer) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    return Buffer.concat([cipher.update(buffer), cipher.final()]);
}

function decrypt(buffer) {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    return Buffer.concat([decipher.update(buffer), decipher.final()]);
}

function hash(buffer) {
    return crypto.createHash("sha256").update(buffer).digest("hex");
}

module.exports = { encrypt, decrypt, hash };


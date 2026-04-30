const { Router } = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const config = require("../config");

const router = Router();

function timingSafeCompare(a, b) {
  const aHash = crypto.createHash("sha256").update(a).digest();
  const bHash = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(aHash, bHash);
}

router.post("/login", (req, res) => {
  const { password } = req.body;
  if (!password || !timingSafeCompare(password, config.adminPassword)) {
    return res.status(401).json({ error: "Invalid password" });
  }
  const token = jwt.sign({ sub: "admin" }, config.authSecret, { expiresIn: "12h" });
  res.json({ token });
});

module.exports = router;
module.exports.timingSafeCompare = timingSafeCompare;

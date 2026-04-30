const { Router } = require("express");
const crypto = require("crypto");
const { invalidateArticlesCache } = require("../cache/redis");
const config = require("../config");

const router = Router();

router.use((req, res, next) => {
  const token = req.headers["x-internal-token"];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  const a = crypto.createHash("sha256").update(token).digest();
  const b = crypto.createHash("sha256").update(config.internalSecret).digest();
  if (!crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

router.post("/cache/invalidate", async (req, res) => {
  await invalidateArticlesCache();
  res.json({ invalidated: true });
});

module.exports = router;

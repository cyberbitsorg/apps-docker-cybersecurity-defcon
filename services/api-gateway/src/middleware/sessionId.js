const { v4: uuidv4 } = require("uuid");

module.exports = function sessionIdMiddleware(req, res, next) {
  req.sessionId = uuidv4();
  next();
};

module.exports = function errorHandler(err, req, res, next) {
  console.error(err.message);
  const status = err.status || 500;
  res.status(status).json({
    error: status < 500 ? err.message : "Internal server error",
  });
};

const pool = require("../pool");

const LEVEL_LABELS = {
  1: "Cocked Pistol",
  2: "Fast Pace",
  3: "Round House",
  4: "Double Take",
  5: "Fade Out",
};
const LEVEL_COLORS = {
  1: "#ffffff",
  2: "#dc2626",
  3: "#eab308",
  4: "#22c55e",
  5: "#3b82f6",
};

async function getCurrentDefcon() {
  const result = await pool.query(
    `SELECT score, level, computed_at, article_window, contributing_factors
     FROM defcon_history
     ORDER BY computed_at DESC
     LIMIT 1`
  );

  if (!result.rows.length) {
    return { score: 0, level: 5, label: "Fade Out", color: "#3b82f6", computed_at: null, factors: {}, trend: "stable" };
  }

  const row = result.rows[0];

  // Determine trend from last 3 readings
  const trendResult = await pool.query(
    `SELECT score FROM defcon_history ORDER BY computed_at DESC LIMIT 3`
  );
  const scores = trendResult.rows.map((r) => parseFloat(r.score));
  let trend = "stable";
  if (scores.length >= 2) {
    const delta = scores[0] - scores[scores.length - 1];
    if (delta > 5) trend = "rising";
    else if (delta < -5) trend = "falling";
  }

  return {
    score: parseFloat(row.score),
    level: row.level,
    label: LEVEL_LABELS[row.level] || "UNKNOWN",
    color: LEVEL_COLORS[row.level] || "#6b7280",
    computed_at: row.computed_at,
    factors: row.contributing_factors || {},
    trend,
  };
}

async function getDefconHistory(hours = 24) {
  const result = await pool.query(
    `SELECT score, level, computed_at
     FROM defcon_history
     WHERE computed_at >= NOW() - ($1 || ' hours')::interval
     ORDER BY computed_at ASC`,
    [hours]
  );

  return result.rows.map((r) => ({
    score: parseFloat(r.score),
    level: r.level,
    computed_at: r.computed_at,
    color: LEVEL_COLORS[r.level],
  }));
}

module.exports = { getCurrentDefcon, getDefconHistory };

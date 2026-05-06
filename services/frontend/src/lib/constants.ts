export const SOURCE_COLORS: Record<string, string> = {
  bleeping_computer: "#f97316",  // orange
  hacker_news:       "#8b5cf6",  // violet
  hackread:          "#ec4899",  // pink
  security_affairs:  "#e11d48",  // rose
  the_register:      "#06b6d4",  // cyan
};

export const SOURCE_LABELS: Record<string, string> = {
  bleeping_computer: "BC",
  hacker_news:       "HN",
  hackread:          "HR",
  security_affairs:  "SA",
  the_register:      "TR",
};

export const DEFCON_LEVELS = {
  1: { term: "Cocked Pistol", color: "#ffffff", bg: "bg-white/10",      border: "border-white/30",      text: "text-white"       },
  2: { term: "Fast Pace",     color: "#dc2626", bg: "bg-red-600/10",    border: "border-red-600/30",    text: "text-red-400"     },
  3: { term: "Round House",   color: "#eab308", bg: "bg-yellow-500/10", border: "border-yellow-500/30", text: "text-yellow-400"  },
  4: { term: "Double Take",   color: "#22c55e", bg: "bg-green-500/10",  border: "border-green-500/30",  text: "text-green-400"   },
  5: { term: "Fade Out",      color: "#3b82f6", bg: "bg-blue-500/10",   border: "border-blue-500/30",   text: "text-blue-400"    },
} as const;

export function scoreToLevel(score: number): 1 | 2 | 3 | 4 | 5 {
  if (score >= 80) return 1;
  if (score >= 60) return 2;
  if (score >= 40) return 3;
  if (score >= 20) return 4;
  return 5;
}

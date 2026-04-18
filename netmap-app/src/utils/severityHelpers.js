/**
 * Severity-related helper functions and constants
 */

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_CONFIG = {
  critical: {
    label: "Critical",
    color: "var(--critical)",
    glow: "var(--critical-glow)",
    bg: "rgba(244, 63, 94, 0.1)",
    icon: "🔴",
  },
  high: {
    label: "High",
    color: "var(--high)",
    glow: "var(--high-glow)",
    bg: "rgba(249, 115, 22, 0.1)",
    icon: "🟠",
  },
  medium: {
    label: "Medium",
    color: "var(--medium)",
    glow: "var(--medium-glow)",
    bg: "rgba(234, 179, 8, 0.1)",
    icon: "🟡",
  },
  low: {
    label: "Low",
    color: "var(--low)",
    glow: "var(--low-glow)",
    bg: "rgba(34, 197, 94, 0.1)",
    icon: "🟢",
  },
  info: {
    label: "Info",
    color: "var(--info)",
    glow: "rgba(59, 130, 246, 0.2)",
    bg: "rgba(59, 130, 246, 0.1)",
    icon: "🔵",
  },
};

/**
 * Sort findings by severity (critical first)
 */
export function sortBySeverity(findings) {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf((a.severity || "low").toLowerCase()) -
      SEVERITY_ORDER.indexOf((b.severity || "low").toLowerCase())
  );
}

/**
 * Count findings by severity
 */
export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => {
    const sev = (f.severity || "low").toLowerCase();
    if (counts[sev] !== undefined) {
      counts[sev]++;
    }
  });
  return counts;
}

/**
 * Get unique hosts from findings
 */
export function getUniqueHosts(findings) {
  return [...new Set(findings.map((f) => f.host))];
}

/**
 * Get highest severity for a given host
 */
export function getHostSeverity(findings, host) {
  const hostFindings = findings.filter((f) => f.host === host);
  if (hostFindings.length === 0) return "low";
  
  for (const severity of SEVERITY_ORDER) {
    if (hostFindings.some((f) => (f.severity || "low").toLowerCase() === severity)) {
      return severity;
    }
  }
  return "low";
}

/**
 * Get the raw color value for a severity level (for canvas rendering)
 */
export function getSeverityColor(severity) {
  const colors = {
    critical: "#FF3B5C",
    high:     "#FF7043",
    medium:   "#FFB300",
    low:      "#00E5FF",   // neon blue
    info:     "#3B82F6",
  };
  return colors[(severity || "low").toLowerCase()] || colors.low;
}

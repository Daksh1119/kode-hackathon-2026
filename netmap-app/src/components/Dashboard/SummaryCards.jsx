import React from "react";
import { Globe, AlertTriangle, AlertCircle, Info, ShieldAlert } from "lucide-react";
import { countBySeverity, SEVERITY_CONFIG } from "../../utils/severityHelpers";

const CARD_DEFS = [
  {
    key: "total",
    label: "Assets Found",
    icon: Globe,
    filter: "all",
    colorVar: "var(--info)",
    glowVar: "rgba(59, 130, 246, 0.2)",
    bgVar: "rgba(59, 130, 246, 0.08)",
  },
  {
    key: "critical",
    label: "Critical",
    icon: ShieldAlert,
    filter: "critical",
    colorVar: "var(--critical)",
    glowVar: "var(--critical-glow)",
    bgVar: "rgba(244, 63, 94, 0.08)",
  },
  {
    key: "high",
    label: "High",
    icon: AlertTriangle,
    filter: "high",
    colorVar: "var(--high)",
    glowVar: "var(--high-glow)",
    bgVar: "rgba(249, 115, 22, 0.08)",
  },
  {
    key: "medium",
    label: "Medium",
    icon: AlertCircle,
    filter: "medium",
    colorVar: "var(--medium)",
    glowVar: "var(--medium-glow)",
    bgVar: "rgba(234, 179, 8, 0.08)",
  },
  {
    key: "low",
    label: "Low",
    icon: Info,
    filter: "low",
    colorVar: "var(--low)",
    glowVar: "var(--low-glow)",
    bgVar: "rgba(34, 197, 94, 0.08)",
  },
];

export default function SummaryCards({ findings, activeFilter, onFilterChange }) {
  const counts = countBySeverity(findings);
  counts.total = findings.length;

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(5, 1fr)",
        gap: 16,
      }}
    >
      {CARD_DEFS.map((card, index) => {
        const Icon = card.icon;
        const isActive = activeFilter === card.filter;
        const count = counts[card.key] || 0;

        return (
          <button
            key={card.key}
            id={`summary-card-${card.key}`}
            onClick={() => onFilterChange(isActive ? "all" : card.filter)}
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-start",
              gap: 8,
              padding: "20px 24px",
              background: "var(--bg-surface)",
              border: isActive
                ? `1px solid ${card.colorVar}`
                : "1px solid var(--border-subtle)",
              borderRadius: "var(--radius-lg)",
              cursor: "pointer",
              transition: "all var(--duration-base) var(--ease-smooth)",
              boxShadow: isActive
                ? `0 0 20px ${card.glowVar}`
                : "none",
              transform: "translateY(0)",
              textAlign: "left",
              fontFamily: "var(--font-body)",
              animation: `fadeUp 0.4s var(--ease-sharp) ${index * 80}ms both`,
            }}
            onMouseEnter={(e) => {
              if (!isActive) {
                e.currentTarget.style.borderColor = "var(--border-active)";
                e.currentTarget.style.transform = "translateY(-2px)";
              }
            }}
            onMouseLeave={(e) => {
              if (!isActive) {
                e.currentTarget.style.borderColor = "var(--border-subtle)";
                e.currentTarget.style.transform = "translateY(0)";
              }
            }}
          >
            <Icon size={24} style={{ color: card.colorVar }} />
            <span
              className="font-display"
              style={{
                fontSize: "var(--text-2xl)",
                fontWeight: 700,
                color: "var(--text-primary)",
                lineHeight: 1,
              }}
            >
              {count}
            </span>
            <span
              className="font-mono"
              style={{
                fontSize: "var(--text-xs)",
                color: "var(--text-muted)",
                textTransform: "uppercase",
              }}
            >
              {card.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}

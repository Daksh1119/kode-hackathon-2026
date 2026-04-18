import React, { useEffect, useRef } from "react";
import { Globe, AlertTriangle, AlertCircle, Info, ShieldAlert, Cloud, Unplug } from "lucide-react";
import { countBySeverity } from "../../utils/severityHelpers";

const CARD_DEFS = [
  {
    key: "assets",
    label: "Total Assets",
    icon: Globe,
    filter: "all",
    colorVar: "var(--info)",
    glowVar: "rgba(68, 138, 255, 0.2)",
    getValue: (findings) => [...new Set(findings.map((f) => f.host))].length,
  },
  {
    key: "high",
    label: "HIGH",
    icon: AlertTriangle,
    filter: "high",
    colorVar: "var(--high)",
    glowVar: "rgba(255, 112, 67, 0.2)",
    getValue: (_, counts) => counts.high,
  },
  {
    key: "medium",
    label: "MEDIUM",
    icon: AlertCircle,
    filter: "medium",
    colorVar: "var(--medium)",
    glowVar: "rgba(255, 179, 0, 0.2)",
    getValue: (_, counts) => counts.medium,
  },
  {
    key: "low",
    label: "LOW",
    icon: Info,
    filter: "low",
    colorVar: "var(--low)",
    glowVar: "rgba(0, 229, 255, 0.2)",
    getValue: (_, counts) => counts.low,
  },
  {
    key: "cloud",
    label: "Cloud Issues",
    icon: Cloud,
    filter: "all",
    colorVar: "#4DD0E1",
    glowVar: "rgba(77, 208, 225, 0.2)",
    getValue: (findings) => findings.filter((f) => f.source === "cloud").length,
  },
  {
    key: "ports",
    label: "Open Ports",
    icon: Unplug,
    filter: "all",
    colorVar: "var(--accent)",
    glowVar: "rgba(0, 229, 255, 0.2)",
    getValue: (findings) => findings.filter((f) => f.port !== null && f.port !== undefined).length,
  },
];

// Animated counter hook
function useCountUp(target, duration = 800) {
  const [value, setValue] = React.useState(0);
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) cancelAnimationFrame(ref.current);
    let startTime = null;
    const step = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      setValue(Math.floor(progress * target));
      if (progress < 1) ref.current = requestAnimationFrame(step);
    };
    ref.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(ref.current);
  }, [target, duration]);
  return value;
}

function AnimatedCount({ target }) {
  const value = useCountUp(target);
  return <>{value}</>;
}

export default function SummaryCards({ findings, activeFilter, onFilterChange }) {
  const counts = countBySeverity(findings);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(6, 1fr)",
        gap: 14,
      }}
    >
      {CARD_DEFS.map((card, index) => {
        const Icon = card.icon;
        const isActive = activeFilter === card.filter && card.filter !== "all";
        const count = card.getValue(findings, counts);

        return (
          <button
            key={card.key}
            id={`summary-card-${card.key}`}
            onClick={() =>
              card.filter !== "all"
                ? onFilterChange(isActive ? "all" : card.filter)
                : undefined
            }
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-start",
              gap: 6,
              padding: "20px 20px",
              background: isActive
                ? `color-mix(in srgb, ${card.colorVar} 7%, var(--surface))`
                : "var(--surface)",
              border: isActive
                ? `1px solid ${card.colorVar}`
                : "1px solid var(--border)",
              borderRadius: 12,
              cursor: card.filter !== "all" ? "pointer" : "default",
              transition: "all var(--duration-base) var(--ease-smooth)",
              boxShadow: isActive ? `0 0 22px ${card.glowVar}, inset 0 1px 0 rgba(255,255,255,0.05)` : "none",
              textAlign: "left",
              fontFamily: "var(--font-body)",
              animation: `fadeUp 0.4s var(--ease-sharp) ${index * 60}ms both`,
            }}
            onMouseEnter={(e) => {
              if (!isActive && card.filter !== "all") {
                e.currentTarget.style.borderColor = "var(--border-hover)";
                e.currentTarget.style.transform = "translateY(-2px)";
              }
            }}
            onMouseLeave={(e) => {
              if (!isActive && card.filter !== "all") {
                e.currentTarget.style.borderColor = "var(--border)";
                e.currentTarget.style.transform = "translateY(0)";
              }
            }}
          >
            <Icon size={20} style={{ color: card.colorVar }} />
            <span
              className="font-display"
              style={{
                fontSize: 32,
                fontWeight: 700,
                color: isActive ? card.colorVar : "var(--text)",
                lineHeight: 1,
                transition: "color var(--duration-base)",
              }}
            >
              <AnimatedCount target={count} />
            </span>
            <span
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-3)",
                textTransform: "uppercase",
                letterSpacing: "0.08em",
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

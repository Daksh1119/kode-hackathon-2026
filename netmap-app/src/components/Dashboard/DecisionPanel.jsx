import React, { useState } from "react";
import {
  Zap,
  AlertTriangle,
  Copy,
  Download,
  Check,
} from "lucide-react";
import { countBySeverity, sortBySeverity } from "../../utils/severityHelpers";

export default function DecisionPanel({
  findings,
  onFindingClick,
  onDownload,
  onCopy,
}) {
  const [copied, setCopied] = useState(false);

  const counts = countBySeverity(findings);

  // Get top priority items (critical + high)
  const priorityItems = sortBySeverity(findings)
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 5);

  // Risk reduction percentages (simulated)
  const totalWeighted =
    counts.critical * 10 +
    counts.high * 5 +
    counts.medium * 2 +
    counts.low * 1;
  const criticalReduction =
    totalWeighted > 0
      ? Math.round(((counts.critical * 10) / totalWeighted) * 100)
      : 0;
  const highReduction =
    totalWeighted > 0
      ? Math.round(((counts.high * 5) / totalWeighted) * 100)
      : 0;

  const handleCopy = async () => {
    const success = await onCopy();
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div
      style={{
        position: "sticky",
        top: 80,
        background: "var(--bg-surface)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "var(--radius-lg)",
        padding: "24px",
        display: "flex",
        flexDirection: "column",
        gap: 24,
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <Zap size={14} style={{ color: "var(--accent)" }} />
        <h3
          className="font-mono"
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--accent)",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
          }}
        >
          Decision Brief
        </h3>
      </div>

      {/* Fix First */}
      <div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 16,
          }}
        >
          <AlertTriangle size={14} style={{ color: "var(--critical)" }} />
          <span
            style={{
              fontSize: "var(--text-xs)",
              fontWeight: 500,
              color: "var(--text-primary)",
            }}
          >
            Fix First
          </span>
          <span
            className="font-mono"
            style={{
              fontSize: "var(--text-xs)",
              color: "var(--critical)",
              marginLeft: 4,
            }}
          >
            · HIGH IMPACT
          </span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {priorityItems.map((item, index) => {
            const borderColor =
              item.severity === "critical"
                ? "var(--critical)"
                : "var(--high)";
            return (
              <button
                key={item.id}
                onClick={() => onFindingClick(item)}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 10,
                  padding: "10px 12px",
                  background: "transparent",
                  border: "none",
                  borderLeft: `2px solid ${borderColor}`,
                  borderRadius: "0 var(--radius-sm) var(--radius-sm) 0",
                  cursor: "pointer",
                  textAlign: "left",
                  fontFamily: "var(--font-body)",
                  transition: "background var(--duration-fast)",
                  width: "100%",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "var(--bg-elevated)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "transparent";
                }}
              >
                <span
                  className="font-mono"
                  style={{
                    fontSize: "var(--text-xs)",
                    color: "var(--text-muted)",
                    flexShrink: 0,
                    marginTop: 1,
                  }}
                >
                  {index + 1}
                </span>
                <div>
                  <div
                    style={{
                      fontSize: "var(--text-sm)",
                      color: "var(--text-primary)",
                      fontWeight: 500,
                      lineHeight: 1.4,
                    }}
                  >
                    {item.title}
                  </div>
                  <div
                    className="font-mono"
                    style={{
                      fontSize: "var(--text-xs)",
                      color: "var(--text-muted)",
                      marginTop: 2,
                    }}
                  >
                    {item.host}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Risk Reduction */}
      <div>
        <h4
          className="font-mono"
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--text-muted)",
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            marginBottom: 12,
          }}
        >
          Risk Reduction if fixed
        </h4>

        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <RiskBar
            label="Critical"
            percentage={criticalReduction}
            color="var(--critical)"
          />
          <RiskBar
            label="High"
            percentage={highReduction}
            color="var(--high)"
          />
        </div>
      </div>

      {/* Export Buttons */}
      <div
        style={{
          display: "flex",
          gap: 8,
          paddingTop: 16,
          borderTop: "1px solid var(--border-subtle)",
        }}
      >
        <button
          onClick={handleCopy}
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 6,
            padding: "8px 12px",
            fontSize: "var(--text-xs)",
            fontFamily: "var(--font-body)",
            color: copied ? "var(--low)" : "var(--accent)",
            background: "transparent",
            border: `1px solid ${copied ? "var(--low)" : "var(--accent)"}`,
            borderRadius: "var(--radius-md)",
            cursor: "pointer",
            transition: "all var(--duration-base)",
          }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? "Copied!" : "Copy Summary"}
        </button>
        <button
          onClick={onDownload}
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 6,
            padding: "8px 12px",
            fontSize: "var(--text-xs)",
            fontFamily: "var(--font-body)",
            color: "#0B0F17",
            background: "var(--accent)",
            border: "1px solid var(--accent)",
            borderRadius: "var(--radius-md)",
            cursor: "pointer",
            fontWeight: 500,
            transition: "all var(--duration-base)",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.opacity = "0.9";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.opacity = "1";
          }}
        >
          <Download size={12} />
          Report
        </button>
      </div>
    </div>
  );
}

function RiskBar({ label, percentage, color }) {
  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: 4,
        }}
      >
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--text-secondary)",
          }}
        >
          {label}
        </span>
        <span
          className="font-mono"
          style={{
            fontSize: "var(--text-xs)",
            color: color,
          }}
        >
          {percentage}%
        </span>
      </div>
      <div
        style={{
          height: 6,
          background: "var(--bg-elevated)",
          borderRadius: 3,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${percentage}%`,
            background: color,
            borderRadius: 3,
            transition: "width 600ms var(--ease-smooth)",
            boxShadow: `0 0 8px ${color}40`,
          }}
        />
      </div>
    </div>
  );
}

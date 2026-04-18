import React, { useState } from "react";
import { Zap, AlertTriangle, Copy, Download, Check } from "lucide-react";
import { countBySeverity, sortBySeverity } from "../../utils/severityHelpers";

const EST_TIMES = {
  "Public Admin Panel Detected": "15 min",
  "Sensitive Port 21 Open — FTP": "5 min",
  "Sensitive Port 3389 Open — RDP": "5 min",
  "Sensitive Port 135 Open — MSRPC": "10 min",
  "Sensitive Port 25 Open — SMTP": "20 min",
  "Public Cloud Bucket Exposed — S3": "10 min",
  "Bucket Directory Listing Enabled — S3": "5 min",
};

export default function DecisionPanel({ findings, onFindingClick, onDownload, onCopy }) {
  const [copied, setCopied] = useState(false);

  const counts = countBySeverity(findings);

  // Top critical/high items
  const priorityItems = sortBySeverity(findings)
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 5);

  // Risk meter
  const highCount = counts.high;
  const medCount = counts.medium;
  const totalFindings = findings.length;
  const riskScore = totalFindings > 0
    ? Math.min(Math.round(((counts.critical * 10 + counts.high * 5 + counts.medium * 2) / (totalFindings * 10)) * 100), 99)
    : 0;

  // Estimate total fix time
  const estHours = (counts.critical * 0.5 + counts.high * 0.25 + counts.medium * 0.15).toFixed(1);

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
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 10,
        padding: "24px",
        display: "flex",
        flexDirection: "column",
        gap: 20,
        maxHeight: "calc(100vh - 120px)",
        overflowY: "auto",
      }}
    >
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Zap size={14} style={{ color: "var(--accent)" }} />
        <h3
          className="font-mono"
          style={{
            fontSize: 11,
            color: "var(--accent)",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
          }}
        >
          ⚡ Priority Actions
        </h3>
      </div>

      {/* Fix Immediately section */}
      <div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            marginBottom: 12,
          }}
        >
          <AlertTriangle size={12} style={{ color: "var(--critical)" }} />
          <span
            className="font-mono"
            style={{
              fontSize: 10,
              color: "var(--critical)",
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              fontWeight: 600,
            }}
          >
            🚨 Fix Immediately
          </span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {priorityItems.map((item, index) => {
            const borderColor =
              item.severity === "critical" ? "var(--critical)" : "var(--high)";
            const est = EST_TIMES[item.title] || "10 min";
            return (
              <button
                key={item.id}
                onClick={() => onFindingClick(item)}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 10,
                  padding: "12px",
                  background: "var(--elevated)",
                  border: "none",
                  borderLeft: `3px solid ${borderColor}`,
                  borderRadius: "0 6px 6px 0",
                  cursor: "pointer",
                  textAlign: "left",
                  fontFamily: "var(--font-body)",
                  transition: "background var(--duration-fast)",
                  width: "100%",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(255,255,255,0.05)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "var(--elevated)";
                }}
              >
                <span
                  className="font-mono"
                  style={{
                    fontSize: 11,
                    color: "var(--text-3)",
                    flexShrink: 0,
                    marginTop: 1,
                    minWidth: 16,
                  }}
                >
                  {index + 1}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 13,
                      color: "var(--text)",
                      fontWeight: 500,
                      lineHeight: 1.4,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {item.title}
                  </div>
                  <div
                    className="font-mono"
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      marginTop: 3,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 11,
                        color: "var(--accent)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {item.host}
                    </span>
                    <span style={{ fontSize: 10, color: "var(--text-3)", flexShrink: 0, marginLeft: 6 }}>
                      ~{est}
                    </span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Risk Meter */}
      <div>
        <h4
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-3)",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            marginBottom: 12,
          }}
        >
          Risk If Left Unfixed
        </h4>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <RiskBar label="Critical exposure" value={highCount} max={10} color="var(--critical)" suffix={`HIGH ${highCount}`} />
          <RiskBar label="Unencrypted traffic" value={medCount} max={6} color="var(--medium)" suffix={`MED ${medCount}`} />
          <RiskBar label="Overall risk score" value={riskScore} max={100} color="var(--high)" suffix={`${riskScore}%`} />
        </div>
      </div>

      {/* Est. fix time */}
      <div
        className="font-mono"
        style={{
          fontSize: 12,
          color: "var(--text-2)",
          padding: "12px 0",
          borderTop: "1px solid var(--border)",
        }}
      >
        Est. total fix time:{" "}
        <span style={{ color: "var(--text)" }}>~{estHours} hours</span>
      </div>

      {/* Export Buttons */}
      <div style={{ display: "flex", gap: 8 }}>
        <button
          onClick={handleCopy}
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 6,
            padding: "8px 10px",
            fontSize: 12,
            fontFamily: "var(--font-display)",
            fontWeight: 600,
            color: copied ? "var(--low)" : "var(--accent)",
            background: "transparent",
            border: `1px solid ${copied ? "var(--low)" : "var(--accent)"}`,
            borderRadius: 8,
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
            padding: "8px 10px",
            fontSize: 12,
            fontFamily: "var(--font-display)",
            fontWeight: 600,
            color: "#0A0E1A",
            background: "var(--accent)",
            border: "1px solid var(--accent)",
            borderRadius: 8,
            cursor: "pointer",
            transition: "all var(--duration-base)",
          }}
          onMouseEnter={(e) => { e.currentTarget.style.opacity = "0.9"; }}
          onMouseLeave={(e) => { e.currentTarget.style.opacity = "1"; }}
        >
          <Download size={12} />
          Report
        </button>
      </div>
    </div>
  );
}

function RiskBar({ label, value, max, color, suffix }) {
  const pct = Math.min(Math.round((value / max) * 100), 100);
  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: 5,
        }}
      >
        <span style={{ fontSize: 12, color: "var(--text-2)", fontFamily: "var(--font-body)" }}>
          {label}
        </span>
        <span className="font-mono" style={{ fontSize: 11, color }}>
          {suffix}
        </span>
      </div>
      <div
        style={{
          height: 6,
          background: "var(--elevated)",
          borderRadius: 3,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
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

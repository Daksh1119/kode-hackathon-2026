import React from "react";
import { Check, Loader2, Circle } from "lucide-react";
import { SCAN_STAGES } from "../../data/mockFindings";

export default function StageTracker({
  stageStates,
  domain,
  elapsed,
  subsFound,
}) {
  const getIcon = (state) => {
    switch (state) {
      case "complete":
        return <Check size={16} style={{ color: "var(--low)" }} />;
      case "running":
        return (
          <Loader2
            size={16}
            style={{
              color: "var(--accent)",
              animation: "spin 1s linear infinite",
            }}
          />
        );
      default:
        return <Circle size={16} style={{ color: "var(--text-muted)" }} />;
    }
  };

  const getStateLabel = (state) => {
    switch (state) {
      case "complete":
        return "COMPLETE";
      case "running":
        return "RUNNING...";
      default:
        return "PENDING";
    }
  };

  const startTime = new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 0,
      }}
    >
      {/* Title */}
      <h3
        className="font-mono"
        style={{
          fontSize: "var(--text-xs)",
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.15em",
          marginBottom: 16,
        }}
      >
        Scan Stages
      </h3>

      {/* Stage Rows */}
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {SCAN_STAGES.map((stage, index) => {
          const state = stageStates[index];
          const isRunning = state === "running";

          return (
            <div
              key={stage.id}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "12px 16px",
                borderRadius: "var(--radius-md)",
                background: isRunning ? "var(--bg-elevated)" : "transparent",
                borderLeft: isRunning
                  ? "2px solid var(--accent)"
                  : "2px solid transparent",
                transition: "all var(--duration-base) var(--ease-smooth)",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: 12 }}
              >
                {getIcon(state)}
                <div>
                  <div
                    style={{
                      fontSize: "var(--text-sm)",
                      color:
                        state === "pending"
                          ? "var(--text-muted)"
                          : "var(--text-primary)",
                      fontWeight: isRunning ? 500 : 400,
                    }}
                  >
                    {stage.label}
                  </div>
                  <div
                    style={{
                      fontSize: "var(--text-xs)",
                      color: "var(--text-muted)",
                      marginTop: 2,
                    }}
                  >
                    {stage.description}
                  </div>
                </div>
              </div>
              <span
                className="font-mono"
                style={{
                  fontSize: "var(--text-xs)",
                  color:
                    state === "complete"
                      ? "var(--low)"
                      : state === "running"
                        ? "var(--accent)"
                        : "var(--text-muted)",
                  whiteSpace: "nowrap",
                }}
              >
                {getStateLabel(state)}
              </span>
            </div>
          );
        })}
      </div>

      {/* Scan Metadata */}
      <div
        style={{
          marginTop: 24,
          padding: "16px",
          borderTop: "1px solid var(--border-subtle)",
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "auto 1fr",
            gap: "8px 16px",
            fontSize: "var(--text-xs)",
            fontFamily: "var(--font-terminal)",
          }}
        >
          <span style={{ color: "var(--text-secondary)" }}>Target:</span>
          <span style={{ color: "var(--text-primary)" }}>{domain}</span>

          <span style={{ color: "var(--text-secondary)" }}>Started:</span>
          <span style={{ color: "var(--text-primary)" }}>{startTime}</span>

          <span style={{ color: "var(--text-secondary)" }}>Elapsed:</span>
          <span style={{ color: "var(--text-primary)" }}>{elapsed}</span>

          <span style={{ color: "var(--text-secondary)" }}>Subdomains:</span>
          <span style={{ color: "var(--text-primary)" }}>
            {subsFound} found
          </span>
        </div>
      </div>
    </div>
  );
}

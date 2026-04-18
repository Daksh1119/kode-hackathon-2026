import React from "react";
import { Check, Loader2, Circle } from "lucide-react";
import { SCAN_STAGES } from "../../data/mockFindings";

export default function StageTracker({ stageStates, domain, elapsed, subsFound, hostsFound, openPortsFound }) {
  const G = "#AAFF00";

  const getIcon = (state) => {
    switch (state) {
      case "complete":
        return <Check size={16} style={{ color: G }} />;
      case "running":
        return (
          <Loader2
            size={16}
            style={{ color: G, animation: "spin 1s linear infinite" }}
          />
        );
      default:
        return <Circle size={16} style={{ color: "rgba(255,255,255,0.2)" }} />;
    }
  };

  const getStatusLabel = (state) => {
    switch (state) {
      case "complete": return "COMPLETE";
      case "running":  return "RUNNING";
      default:         return "PENDING";
    }
  };

  const getStatusColor = (state) => {
    switch (state) {
      case "complete": return G;
      case "running":  return G;
      default:         return "rgba(255,255,255,0.2)";
    }
  };

  const openPortCount = 9;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Header */}
      <h3
        className="font-mono"
        style={{
          fontSize: 10,
          color: "rgba(170,255,0,0.5)",
          textTransform: "uppercase",
          letterSpacing: "0.2em",
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
                padding: "10px 14px",
                borderRadius: 8,
                background: isRunning ? "rgba(170,255,0,0.06)" : "transparent",
                borderLeft: isRunning
                  ? "2px solid #AAFF00"
                  : "2px solid transparent",
                transition: "all 250ms ease",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                {getIcon(state)}
                <div>
                  <div
                    style={{
                      fontSize: 13,
                      color: state === "pending" ? "rgba(255,255,255,0.3)" : "#fff",
                      fontFamily: "var(--font-body)",
                      fontWeight: isRunning ? 600 : 400,
                    }}
                  >
                    {stage.label}
                  </div>
                  <div
                    className="font-mono"
                    style={{
                      fontSize: 11,
                      color: "var(--text-3)",
                      marginTop: 1,
                    }}
                  >
                    {stage.description}
                  </div>
                </div>
              </div>
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  color: getStatusColor(state),
                  letterSpacing: "0.08em",
                  whiteSpace: "nowrap",
                }}
              >
                {getStatusLabel(state)}
              </span>
            </div>
          );
        })}
      </div>

      {/* Scan Stats */}
      <div
        style={{
          marginTop: 24,
          padding: "16px",
          background: "rgba(170,255,0,0.04)",
          borderRadius: 8,
          border: "1px solid rgba(170,255,0,0.1)",
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "auto 1fr",
            gap: "8px 16px",
            fontSize: 12,
          }}
        >
          {[
            ["Target", domain || "—"],
            ["Elapsed", elapsed],
            ["Hosts", `${hostsFound || subsFound} found`],
            ["Open Ports", `${openPortsFound} detected`],
          ].map(([label, value]) => (
            <React.Fragment key={label}>
              <span className="font-mono" style={{ color: "rgba(170,255,0,0.45)" }}>{label}</span>
              <span className="font-mono" style={{ color: "#fff" }}>{value}</span>
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  );
}

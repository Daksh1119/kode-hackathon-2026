import React from "react";
import GlobalProgressBar from "./GlobalProgressBar";
import StageTracker from "./StageTracker";
import LogStream from "./LogStream";

export default function ScanScreen({
  progress,
  logs,
  stageStates,
  domain,
  elapsed,
  subsFound,
}) {
  return (
    <div
      style={{
        minHeight: "100vh",
        paddingTop: 60,
        animation: "fadeIn 0.4s var(--ease-smooth)",
      }}
    >
      <GlobalProgressBar progress={progress} />

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "35% 1fr",
          gap: 24,
          maxWidth: "var(--max-width)",
          margin: "0 auto",
          padding: "24px",
          minHeight: "calc(100vh - 60px)",
        }}
      >
        {/* Left Column — Stage Tracker */}
        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "var(--radius-lg)",
            padding: "24px",
          }}
        >
          <StageTracker
            stageStates={stageStates}
            domain={domain}
            elapsed={elapsed}
            subsFound={subsFound}
          />
        </div>

        {/* Right Column — Log Stream */}
        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "var(--radius-lg)",
            padding: "24px",
          }}
        >
          <LogStream logs={logs} isRunning={true} />
        </div>
      </div>
    </div>
  );
}

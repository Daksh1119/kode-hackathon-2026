import React from "react";

export default function GlobalProgressBar({ progress }) {
  return (
    <div
      style={{
        position: "fixed",
        top: 56,
        left: 0,
        right: 0,
        height: 3,
        background: "var(--surface)",
        zIndex: 99,
      }}
    >
      <div
        style={{
          height: "100%",
          width: `${progress}%`,
          background: "var(--accent)",
          transition: "width 300ms ease",
          position: "relative",
        }}
      >
        {/* Glowing dot at leading edge */}
        {progress > 0 && progress < 100 && (
          <div
            style={{
              position: "absolute",
              right: -2,
              top: -1,
              width: 5,
              height: 5,
              borderRadius: "50%",
              background: "var(--accent)",
              boxShadow: "0 0 8px var(--accent), 0 0 20px var(--accent)",
              animation: "glowPulse 1s ease-in-out infinite",
            }}
          />
        )}
        {progress >= 100 && (
          <div
            style={{
              position: "absolute",
              inset: 0,
              background: "var(--accent)",
              animation: "progressGlow 1s ease-in-out",
            }}
          />
        )}
      </div>
      {/* Progress label */}
      <div
        style={{
          position: "absolute",
          right: 16,
          top: 4,
        }}
      >
        <span
          className="font-mono"
          style={{
            fontSize: 11,
            color: "var(--accent)",
            letterSpacing: "0.1em",
          }}
        >
          {progress < 100 ? `SCANNING... ${progress}%` : "COMPLETE"}
        </span>
      </div>
    </div>
  );
}

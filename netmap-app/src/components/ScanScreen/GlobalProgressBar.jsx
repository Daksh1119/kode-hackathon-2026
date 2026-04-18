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
        background: "var(--border-subtle)",
        zIndex: 99,
      }}
    >
      <div
        style={{
          height: "100%",
          width: `${progress}%`,
          background: "var(--accent)",
          transition: "width 400ms var(--ease-smooth)",
          position: "relative",
        }}
      >
        {/* Glowing dot at the leading edge */}
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
              boxShadow: "0 0 8px var(--accent), 0 0 16px var(--accent-glow)",
              animation: "glowPulse 1.5s ease-in-out infinite",
            }}
          />
        )}
        {/* Completion glow */}
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
    </div>
  );
}

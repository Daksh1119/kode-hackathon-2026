import React from "react";
import { RotateCcw } from "lucide-react";

// Hexagon SVG logo
function HexLogo() {
  return (
    <svg width="24" height="24" viewBox="0 0 28 28" fill="none">
      <polygon
        points="14,2 25,8 25,20 14,26 3,20 3,8"
        stroke="#00E5FF"
        strokeWidth="1.5"
        fill="none"
      />
      <circle cx="14" cy="14" r="4" fill="#00E5FF"/>
    </svg>
  );
}

export default function Navbar({ scanStatus, onNewScan }) {
  return (
    <nav
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        height: 56,
        zIndex: 100,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 24px",
        background: "rgba(5, 9, 5, 0.92)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        borderBottom: "1px solid rgba(77, 179, 126, 0.2)",
        boxShadow: "0 1px 0 0 rgba(77, 179, 126, 0.1)",
      }}
    >
      {/* Left — Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <HexLogo />
        <span
          className="font-display"
          style={{
            fontSize: "1.05rem",
            fontWeight: 800,
            letterSpacing: "0.15em",
            color: "var(--text)",
          }}
        >
          NETMAP
        </span>
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-3)",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            marginLeft: 4,
          }}
        >
          Attack Surface Intelligence
        </span>
      </div>

      {/* Right */}
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <span
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-3)" }}
        >
          v1.0 · PASSIVE
        </span>

        {scanStatus === "done" && (
          <button
            onClick={onNewScan}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "6px 14px",
              fontSize: 12,
              fontFamily: "var(--font-display)",
              fontWeight: 600,
              color: "#4DB37E",
              background: "transparent",
              border: "1px solid #4DB37E",
              borderRadius: 8,
              cursor: "pointer",
              transition: "all var(--duration-base) var(--ease-smooth)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "#4DB37E";
              e.currentTarget.style.color = "#050905";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.color = "#4DB37E";
            }}
          >
            <RotateCcw size={12} />
            New Scan
          </button>
        )}
      </div>
    </nav>
  );
}

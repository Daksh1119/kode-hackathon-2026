import React from "react";
import { Shield, RotateCcw } from "lucide-react";

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
        background: "var(--bg-glass)",
        backdropFilter: "blur(16px)",
        WebkitBackdropFilter: "blur(16px)",
        borderTop: "1px solid var(--accent)",
        borderBottom: "1px solid var(--border-subtle)",
      }}
    >
      {/* Left — Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div
          style={{
            width: 32,
            height: 32,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Shield
            size={22}
            style={{ color: "var(--accent)", strokeWidth: 2.5 }}
          />
        </div>
        <span
          className="font-display"
          style={{
            fontSize: "1.1rem",
            fontWeight: 800,
            letterSpacing: "0.12em",
            color: "var(--text-primary)",
          }}
        >
          NETMAP
        </span>
      </div>

      {/* Right — Version badge + New Scan button */}
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <span
          className="font-mono"
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--text-muted)",
          }}
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
              fontSize: "var(--text-xs)",
              fontFamily: "var(--font-body)",
              color: "var(--accent)",
              background: "transparent",
              border: "1px solid var(--accent)",
              borderRadius: "var(--radius-md)",
              cursor: "pointer",
              transition: "all var(--duration-base) var(--ease-smooth)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "var(--accent)";
              e.currentTarget.style.color = "#0B0F17";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.color = "var(--accent)";
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

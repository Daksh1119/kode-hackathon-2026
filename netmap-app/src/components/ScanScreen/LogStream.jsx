import React, { useEffect, useRef } from "react";
import { Trash2 } from "lucide-react";

const LOG_COLORS = {
  info:  "var(--accent)",
  found: "var(--low)",
  warn:  "var(--medium)",
  error: "var(--critical)",
};

const LOG_PREFIX = {
  info:  "[+]",
  found: "[✓]",
  warn:  "[!]",
  error: "[✗]",
};

export default function LogStream({ logs, isRunning }) {
  const containerRef = useRef(null);
  const [displayLogs, setDisplayLogs] = React.useState([]);
  const [cleared, setCleared] = React.useState(false);

  useEffect(() => {
    if (cleared) {
      setDisplayLogs([]);
    } else {
      setDisplayLogs(logs);
    }
  }, [logs, cleared]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [displayLogs]);

  const handleClear = () => {
    setCleared(true);
    setTimeout(() => setCleared(false), 100);
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "calc(100vh - 100px)",  // fill nearly full viewport height
        background: "#0d0d0d",
        borderRadius: 10,
        overflow: "hidden",
        border: "1px solid rgba(0,229,255,0.15)",
        boxShadow: "0 0 40px rgba(0,229,255,0.05), 0 10px 40px rgba(0,0,0,0.5)",
      }}
    >
      {/* Header (Mac style) */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 16px",
          background: "#1a1a1a",
          borderBottom: "1px solid rgba(0,229,255,0.1)",
          flexShrink: 0,
        }}
      >
        {/* Mac Traffic Lights */}
        <div style={{ display: "flex", gap: "8px", width: "60px" }}>
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#FF5F56" }}></div>
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#FFBD2E" }}></div>
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#27C93F" }}></div>
        </div>

        {/* Title */}
        <div
          className="font-mono"
          style={{
            fontSize: 11,
            color: "#aaa",
            letterSpacing: "0.05em",
            display: "flex",
            alignItems: "center",
            gap: 8,
            flex: 1,
            justifyContent: "center",
          }}
        >
          {isRunning && (
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: "var(--accent)",
                display: "inline-block",
                animation: "glowPulse 1.5s ease-in-out infinite",
              }}
            />
          )}
          bash — live_scan
        </div>
        <button
          onClick={handleClear}
          className="font-mono"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 4,
            padding: "4px 10px",
            fontSize: 11,
          color: "#fff",
            background: "transparent",
            border: "none",
            borderRadius: 4,
            cursor: "pointer",
            transition: "all var(--duration-fast)",
            fontFamily: "var(--font-mono)",
            width: "60px", // Balance the space for flex center
            justifyContent: "flex-end"
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = "#FF5F56";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = "#aaa";
          }}
        >
          <Trash2 size={12} />
        </button>
      </div>

      {/* Log container */}
      <div
        ref={containerRef}
        style={{
          flex: 1,
          padding: "20px 24px",
          overflowY: "auto",
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          lineHeight: 1.7,
          minHeight: 0,   // critical: allows flex child to shrink/scroll
        }}
      >
        {displayLogs.map((log, index) => (
          <div
            key={log.id}
            style={{
              display: "flex",
              gap: 12,
              animation: "logEntry 180ms var(--ease-sharp)",
              marginBottom: 2,
            }}
          >
            <span style={{ color: "#666", flexShrink: 0, minWidth: 70 }}>
              {log.timestamp}
            </span>
            <span
              style={{
                color: LOG_COLORS[log.type],
                flexShrink: 0,
                fontWeight: 500,
                minWidth: 28,
              }}
            >
              {LOG_PREFIX[log.type]}
            </span>
            <span
              style={{
                color:
                  log.type === "error"
                    ? "#FF5F56"
                    : log.type === "warn"
                    ? "#FFBD2E"
                    : "#ddd",
                wordBreak: "break-word",
                whiteSpace: "pre-wrap",
              }}
            >
              {log.message}
            </span>
          </div>
        ))}

        {/* Blinking cursor */}
        {isRunning && (
          <span
            className="cursor"
            style={{
              color: "var(--accent)",
              animation: "blink 1s step-end infinite",
              fontWeight: 700,
            }}
          >
            ▋
          </span>
        )}

        {displayLogs.length === 0 && !isRunning && (
          <div style={{ color: "var(--text-3)", textAlign: "center", padding: "40px 0" }}>
            Waiting for scan to start...
          </div>
        )}
      </div>
    </div>
  );
}

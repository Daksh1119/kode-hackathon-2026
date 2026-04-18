import React, { useEffect, useRef, useState } from "react";
import { Trash2 } from "lucide-react";

const LOG_COLORS = {
  info: "var(--text-terminal)",
  found: "var(--low)",
  warn: "var(--medium)",
  error: "var(--critical)",
};

const LOG_PREFIX = {
  info: "[*]",
  found: "[+]",
  warn: "[!]",
  error: "[✗]",
};

export default function LogStream({ logs, isRunning }) {
  const containerRef = useRef(null);
  const [cleared, setCleared] = useState(false);
  const [displayLogs, setDisplayLogs] = useState([]);

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
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 12,
        }}
      >
        <h3
          className="font-mono"
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--text-muted)",
            textTransform: "uppercase",
            letterSpacing: "0.15em",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          Live Output
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
        </h3>
        <button
          onClick={handleClear}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 4,
            padding: "4px 10px",
            fontSize: "var(--text-xs)",
            fontFamily: "var(--font-body)",
            color: "var(--text-muted)",
            background: "transparent",
            border: "1px solid var(--border-subtle)",
            borderRadius: "var(--radius-sm)",
            cursor: "pointer",
            transition: "all var(--duration-fast)",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "var(--border-active)";
            e.currentTarget.style.color = "var(--text-secondary)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "var(--border-subtle)";
            e.currentTarget.style.color = "var(--text-muted)";
          }}
        >
          <Trash2 size={12} />
          Clear
        </button>
      </div>

      {/* Log Container */}
      <div
        ref={containerRef}
        style={{
          flex: 1,
          background: "var(--bg-void)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-lg)",
          padding: "16px",
          overflowY: "auto",
          fontFamily: "var(--font-terminal)",
          fontSize: "var(--text-sm)",
          lineHeight: 1.8,
          maxHeight: "calc(100vh - 180px)",
          minHeight: 400,
        }}
      >
        {displayLogs.map((log, index) => (
          <div
            key={log.id}
            style={{
              display: "flex",
              gap: 10,
              animation: "logEntry 180ms var(--ease-sharp)",
              whiteSpace: "nowrap",
              overflow: "hidden",
            }}
          >
            <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>
              {log.timestamp}
            </span>
            <span
              style={{
                color: LOG_COLORS[log.type],
                flexShrink: 0,
                fontWeight: 500,
              }}
            >
              {LOG_PREFIX[log.type]}
            </span>
            <span
              style={{
                color:
                  log.type === "error"
                    ? "var(--critical)"
                    : log.type === "warn"
                      ? "var(--medium)"
                      : "var(--text-primary)",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {log.message}
            </span>
          </div>
        ))}

        {/* Blinking cursor on last line */}
        {isRunning && (
          <span
            style={{
              color: "var(--accent)",
              animation: "blink 1s step-end infinite",
              fontWeight: 700,
            }}
          >
            _
          </span>
        )}

        {/* Empty state */}
        {displayLogs.length === 0 && !isRunning && (
          <div
            style={{
              color: "var(--text-muted)",
              textAlign: "center",
              padding: "40px 0",
            }}
          >
            Waiting for scan to start...
          </div>
        )}
      </div>
    </div>
  );
}

import React, { useState, useEffect } from "react";
import { X, Copy, Check, Sparkles, Loader2, Circle } from "lucide-react";
import { SEVERITY_CONFIG } from "../utils/severityHelpers";

export default function DetailDrawer({ finding, onClose }) {
  const [showFix, setShowFix] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [fixCode, setFixCode] = useState("");
  const [copied, setCopied] = useState(false);
  const [isVisible, setIsVisible] = useState(false);

  // Animate in on mount
  useEffect(() => {
    requestAnimationFrame(() => setIsVisible(true));
  }, []);

  // Reset when finding changes
  useEffect(() => {
    setShowFix(false);
    setGenerating(false);
    setFixCode("");
    setCopied(false);
  }, [finding?.id]);

  const handleClose = () => {
    setIsVisible(false);
    setTimeout(onClose, 400);
  };

  const handleGenerateFix = () => {
    setGenerating(true);
    // Simulate AI generation with typewriter effect
    const code = finding.fixCode || "// No fix available for this finding";
    let index = 0;
    setFixCode("");
    setShowFix(true);

    const interval = setInterval(() => {
      if (index < code.length) {
        setFixCode((prev) => prev + code[index]);
        index++;
      } else {
        clearInterval(interval);
        setGenerating(false);
      }
    }, 12);
  };

  const handleCopyCode = async () => {
    try {
      await navigator.clipboard.writeText(fixCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  if (!finding) return null;

  const config = SEVERITY_CONFIG[finding.severity];

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={handleClose}
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.5)",
          backdropFilter: "blur(4px)",
          WebkitBackdropFilter: "blur(4px)",
          zIndex: 200,
          opacity: isVisible ? 1 : 0,
          transition: "opacity 400ms var(--ease-smooth)",
        }}
      />

      {/* Drawer */}
      <div
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: "var(--drawer-w)",
          maxWidth: "100vw",
          background: "var(--bg-surface)",
          borderLeft: "1px solid var(--border-subtle)",
          zIndex: 201,
          overflowY: "auto",
          transform: isVisible ? "translateX(0)" : "translateX(100%)",
          transition: "transform 400ms var(--ease-sharp)",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "20px 24px",
            borderBottom: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 16,
          }}
        >
          <div style={{ flex: 1 }}>
            <h2
              className="font-display"
              style={{
                fontSize: "var(--text-lg)",
                fontWeight: 700,
                color: "var(--text-primary)",
                lineHeight: 1.3,
              }}
            >
              {finding.title}
            </h2>
            <div
              className="font-mono"
              style={{
                fontSize: "var(--text-sm)",
                color: "var(--accent)",
                marginTop: 4,
              }}
            >
              {finding.host}
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12, flexShrink: 0 }}>
            <span
              className={`severity-badge ${finding.severity}`}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <Circle size={8} fill="currentColor" />
              {finding.severity.toUpperCase()}
            </span>
            <button
              onClick={handleClose}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                width: 32,
                height: 32,
                background: "transparent",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-md)",
                cursor: "pointer",
                color: "var(--text-muted)",
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
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Content */}
        <div style={{ padding: "24px" }}>
          {/* What It Is */}
          {finding.whatItIs && (
            <DrawerSection title="What It Is">
              <p
                style={{
                  fontSize: "var(--text-sm)",
                  color: "var(--text-secondary)",
                  lineHeight: 1.7,
                }}
              >
                {finding.whatItIs}
              </p>
            </DrawerSection>
          )}

          {/* Why It Matters */}
          {finding.whyItMatters && (
            <DrawerSection title="Why It Matters">
              <p
                style={{
                  fontSize: "var(--text-sm)",
                  color: "var(--text-secondary)",
                  lineHeight: 1.7,
                }}
              >
                {finding.whyItMatters}
              </p>
            </DrawerSection>
          )}

          {/* What An Attacker Does */}
          {finding.attackerCan && finding.attackerCan.length > 0 && (
            <DrawerSection title="What An Attacker Does">
              <ul
                style={{
                  listStyle: "none",
                  padding: 0,
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                }}
              >
                {finding.attackerCan.map((action, i) => (
                  <li
                    key={i}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 8,
                      fontSize: "var(--text-sm)",
                      color: "var(--text-secondary)",
                      lineHeight: 1.6,
                    }}
                  >
                    <span style={{ color: "var(--critical)", flexShrink: 0 }}>
                      •
                    </span>
                    {action}
                  </li>
                ))}
              </ul>
            </DrawerSection>
          )}

          {/* Recommended Action */}
          <DrawerSection title="Recommended Action">
            <p
              style={{
                fontSize: "var(--text-sm)",
                color: "var(--text-secondary)",
                lineHeight: 1.7,
              }}
            >
              {finding.action}
            </p>
          </DrawerSection>

          {/* AI Fix Block */}
          <div
            style={{
              marginTop: 24,
              padding: "20px",
              background: "var(--bg-elevated)",
              borderRadius: "var(--radius-lg)",
              border: "1px solid var(--border-subtle)",
            }}
          >
            {!showFix ? (
              <div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    marginBottom: 14,
                  }}
                >
                  <Sparkles
                    size={16}
                    style={{ color: "var(--accent)" }}
                  />
                  <span
                    style={{
                      fontSize: "var(--text-sm)",
                      color: "var(--text-primary)",
                      fontWeight: 500,
                    }}
                  >
                    Generate Fix Code
                  </span>
                </div>
                <button
                  onClick={handleGenerateFix}
                  disabled={generating}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "8px 16px",
                    fontSize: "var(--text-sm)",
                    fontFamily: "var(--font-body)",
                    color: "#0B0F17",
                    background: "var(--accent)",
                    border: "none",
                    borderRadius: "var(--radius-md)",
                    cursor: generating ? "wait" : "pointer",
                    fontWeight: 500,
                    transition: "opacity var(--duration-fast)",
                  }}
                  onMouseEnter={(e) => {
                    if (!generating) e.currentTarget.style.opacity = "0.9";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.opacity = "1";
                  }}
                >
                  {generating ? (
                    <>
                      <Loader2
                        size={14}
                        style={{ animation: "spin 1s linear infinite" }}
                      />
                      Generating...
                    </>
                  ) : (
                    "Generate →"
                  )}
                </button>
              </div>
            ) : (
              <div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 12,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                    }}
                  >
                    <Sparkles
                      size={14}
                      style={{ color: "var(--accent)" }}
                    />
                    <span
                      className="font-mono"
                      style={{
                        fontSize: "var(--text-xs)",
                        color: "var(--accent)",
                      }}
                    >
                      FIX CODE
                    </span>
                  </div>
                  <button
                    onClick={handleCopyCode}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 4,
                      padding: "4px 10px",
                      fontSize: "var(--text-xs)",
                      fontFamily: "var(--font-body)",
                      color: copied ? "var(--low)" : "var(--text-muted)",
                      background: "transparent",
                      border: `1px solid ${copied ? "var(--low)" : "var(--border-subtle)"}`,
                      borderRadius: "var(--radius-sm)",
                      cursor: "pointer",
                      transition: "all var(--duration-fast)",
                    }}
                  >
                    {copied ? (
                      <Check size={12} />
                    ) : (
                      <Copy size={12} />
                    )}
                    {copied ? "Copied!" : "Copy"}
                  </button>
                </div>

                <pre
                  style={{
                    background: "#0B0F17",
                    color: "var(--accent)",
                    fontFamily: "var(--font-terminal)",
                    fontSize: "var(--text-xs)",
                    lineHeight: 1.7,
                    padding: "16px",
                    borderRadius: "var(--radius-md)",
                    overflowX: "auto",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                >
                  {fixCode}
                  {generating && (
                    <span
                      style={{
                        color: "var(--accent)",
                        animation: "blink 1s step-end infinite",
                      }}
                    >
                      ▊
                    </span>
                  )}
                </pre>
              </div>
            )}
          </div>

          {/* Source Info */}
          <div
            style={{
              marginTop: 20,
              padding: "12px 0",
              borderTop: "1px solid var(--border-subtle)",
              display: "flex",
              justifyContent: "space-between",
              fontSize: "var(--text-xs)",
              color: "var(--text-muted)",
              fontFamily: "var(--font-terminal)",
            }}
          >
            <span>Source: {finding.source}</span>
            <span>
              {new Date(finding.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>
    </>
  );
}

function DrawerSection({ title, children }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <h4
        className="font-mono"
        style={{
          fontSize: "var(--text-xs)",
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.12em",
          marginBottom: 10,
        }}
      >
        {title}
      </h4>
      {children}
    </div>
  );
}

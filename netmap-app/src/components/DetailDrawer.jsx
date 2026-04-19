import React, { useState, useEffect } from "react";
import { X, Copy, Check, Sparkles, Loader2, Brain } from "lucide-react";
import { SEVERITY_CONFIG } from "../utils/severityHelpers";

export default function DetailDrawer({ finding, onClose }) {
  const [showFix, setShowFix] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [fixCode, setFixCode] = useState("");
  const [copied, setCopied] = useState(false);
  const [isVisible, setIsVisible] = useState(false);

  // Grok AI explanation state
  const [aiExplain, setAiExplain] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  // Animate in
  useEffect(() => {
    requestAnimationFrame(() => setIsVisible(true));
  }, []);

  // Reset on finding change + fetch AI explanation
  useEffect(() => {
    setShowFix(false);
    setGenerating(false);
    setFixCode("");
    setCopied(false);
    setAiExplain(null);

    if (finding?.id) {
      fetchAiExplanation(finding);
    }
  }, [finding?.id]);

  const fetchAiExplanation = async (f) => {
    setAiLoading(true);
    try {
      const res = await fetch("http://localhost:3001/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: f.title,
          description: f.description,
          action: f.action,
          severity: f.severity,
          host: f.host,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiExplain(data);
      }
    } catch (err) {
      console.error("AI explain failed:", err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleClose = () => {
    setIsVisible(false);
    setTimeout(onClose, 400);
  };

  const handleGenerateFix = async () => {
    setGenerating(true);
    setFixCode("");
    setShowFix(true);
    
    let code = finding.fixCode || "";

    if (!code) {
      try {
        const response = await fetch("http://localhost:3001/api/remediate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            title: finding.title,
            description: finding.description,
            host: finding.host
          })
        });
        const data = await response.json();
        code = data.code || "// No remediation generated.";
      } catch (e) {
        code = "// Failed to reach remediation API.";
      }
    }

    let index = 0;
    const interval = setInterval(() => {
      if (index < code.length) {
        setFixCode((prev) => prev + code[index]);
        index++;
      } else {
        clearInterval(interval);
        setGenerating(false);
      }
    }, 10);
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

  const isCloud = finding.source === "cloud";
  const isMobile = window.innerWidth < 768;

  // Decide what to display for "What Is This?" and "How To Fix"
  const displayWhat = aiExplain?.whatIsThis || finding.whatItIs || finding.description;
  const displayFix = aiExplain?.howToFix || finding.action;
  const isGroqPowered = aiExplain?.source === "groq" || aiExplain?.source === "groq-raw";

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={handleClose}
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.55)",
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
          top: "50%",
          left: "50%",
          width: isMobile ? "92%" : "680px",
          maxHeight: "85vh",
          background: "var(--elevated)",
          border: "1px solid var(--border)",
          borderRadius: "16px",
          zIndex: 201,
          overflowY: "auto",
          transform: isVisible
            ? "translate(-50%, -50%) scale(1)"
            : "translate(-50%, -45%) scale(0.96)",
          opacity: isVisible ? 1 : 0,
          transition: "all 380ms cubic-bezier(0.16, 1, 0.3, 1)",
          boxShadow: "0 32px 64px -12px rgba(0,0,0,0.6)",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "20px 24px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 16,
            position: "sticky",
            top: 0,
            background: "var(--elevated)",
            zIndex: 10,
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            {/* Close button */}
            <button
              onClick={handleClose}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                width: 28,
                height: 28,
                background: "transparent",
                border: "1px solid var(--border)",
                borderRadius: 6,
                cursor: "pointer",
                color: "var(--text-3)",
                transition: "all var(--duration-fast)",
                marginBottom: 14,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = "var(--border-hover)";
                e.currentTarget.style.color = "var(--text)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "var(--border)";
                e.currentTarget.style.color = "var(--text-3)";
              }}
            >
              <X size={14} />
            </button>

            <h2
              className="font-display"
              style={{
                fontSize: 18,
                fontWeight: 700,
                color: "var(--text)",
                lineHeight: 1.3,
                marginBottom: 4,
              }}
            >
              {finding.title}
            </h2>
            <div
              className="font-mono"
              style={{
                fontSize: 13,
                color: "var(--accent)",
              }}
            >
              {finding.host}
            </div>
          </div>

          {/* Severity badge */}
          <div style={{ flexShrink: 0 }}>
            <span className={`severity-badge ${(finding.severity || "low").toLowerCase()}`}>
              ● {finding.severity.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Content */}
        <div style={{ padding: "24px" }}>
          
          {/* Actionable Triage Data */}
          {finding.priority_tier && (
            <DrawerSection title="Prioritization & Triage">
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: 12,
                  background: "var(--bg)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  padding: "16px",
                  marginBottom: 8,
                }}
              >
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>Priority Score</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text)" }}>
                    {finding.priority_score} / 100
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>Recommended SLA</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: "var(--accent)" }}>
                    {finding.remediation?.recommended_sla || "N/A"}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>Fix Efficiency</div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-2)" }}>
                    {finding.fix_efficiency} <span style={{ fontSize: 11, fontWeight: 400, color: "var(--text-3)" }}>pts/effort</span>
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>Routing / Owner</div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-2)" }}>
                    {finding.remediation?.owner_category || "Unassigned"}
                  </div>
                </div>
              </div>
            </DrawerSection>
          )}

          {/* What is this? — AI-powered */}
          <DrawerSection title="What Is This?">
            {aiLoading ? (
              <ShimmerBlock />
            ) : (
              <div>
                {isGroqPowered && (
                  <div style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    padding: "3px 10px",
                    borderRadius: 999,
                    background: "rgba(77,179,126,0.1)",
                    border: "1px solid rgba(77,179,126,0.2)",
                    marginBottom: 10,
                    fontSize: 10,
                    fontWeight: 600,
                    color: "var(--green-accent)",
                    letterSpacing: "0.05em",
                    textTransform: "uppercase",
                  }}>
                    <Brain size={11} />
                    Explained by Groq AI
                  </div>
                )}
                <p style={{ fontSize: 14, color: "var(--text-2)", lineHeight: 1.75, maxWidth: "65ch" }}>
                  {displayWhat}
                </p>
              </div>
            )}
          </DrawerSection>

          {/* Why does it matter? */}
          {finding.whyItMatters && (
            <DrawerSection title="Why Does It Matter?">
              <p style={{ fontSize: 14, color: "var(--text-2)", lineHeight: 1.65, maxWidth: "65ch" }}>
                {finding.whyItMatters}
              </p>
            </DrawerSection>
          )}

          {/* What can an attacker do? */}
          {finding.attackerCan && finding.attackerCan.length > 0 && (
            <DrawerSection title="What Can An Attacker Do?">
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
                      fontSize: 14,
                      color: "var(--text-2)",
                      lineHeight: 1.6,
                    }}
                  >
                    <span style={{ color: "var(--accent)", flexShrink: 0, fontWeight: 700 }}>•</span>
                    {action}
                  </li>
                ))}
              </ul>
            </DrawerSection>
          )}

          {/* How to fix — AI-powered */}
          <DrawerSection title="How To Fix It">
            {aiLoading ? (
              <ShimmerBlock />
            ) : (
              <div>
                {isGroqPowered && (
                  <div style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    padding: "3px 10px",
                    borderRadius: 999,
                    background: "rgba(77,179,126,0.1)",
                    border: "1px solid rgba(77,179,126,0.2)",
                    marginBottom: 10,
                    fontSize: 10,
                    fontWeight: 600,
                    color: "var(--green-accent)",
                    letterSpacing: "0.05em",
                    textTransform: "uppercase",
                  }}>
                    <Brain size={11} />
                    Simplified by Groq AI
                  </div>
                )}
                <p style={{ fontSize: 14, color: "var(--text-2)", lineHeight: 1.75, maxWidth: "65ch" }}>
                  {displayFix}
                </p>
              </div>
            )}
          </DrawerSection>

          {/* Exposed files (cloud findings) */}
          {isCloud && finding.exposedFiles && finding.exposedFiles.length > 0 && (
            <DrawerSection title="Exposed Files (Sample)">
              <div
                style={{
                  background: "var(--bg)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  padding: "12px 16px",
                }}
              >
                {finding.exposedFiles.map((file, i) => (
                  <div
                    key={i}
                    className="font-mono"
                    style={{
                      fontSize: 12,
                      color: "var(--text-2)",
                      padding: "3px 0",
                    }}
                  >
                    📄 {file}
                  </div>
                ))}
                <div
                  className="font-mono"
                  style={{ fontSize: 11, color: "var(--text-3)", marginTop: 6 }}
                >
                  + more objects...
                </div>
              </div>
            </DrawerSection>
          )}

          {/* AI Fix Button */}
          <div
            style={{
              marginTop: 24,
              padding: "20px",
              background: "var(--surface)",
              borderRadius: 10,
              border: "1px solid var(--border)",
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
                  <Sparkles size={16} style={{ color: "var(--accent)" }} />
                  <span
                    className="font-display"
                    style={{ fontSize: 14, color: "var(--text)", fontWeight: 600 }}
                  >
                    Generate Remediation Code
                  </span>
                </div>
                <button
                  onClick={handleGenerateFix}
                  disabled={generating}
                  className="font-display"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: 6,
                    padding: "10px 20px",
                    width: "100%",
                    fontSize: 14,
                    fontWeight: 600,
                    color: "#0A0E1A",
                    background: "var(--accent)",
                    border: "none",
                    borderRadius: 8,
                    cursor: generating ? "wait" : "pointer",
                    fontFamily: "var(--font-display)",
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
                      <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} />
                      Generating...
                    </>
                  ) : (
                    "✦ Generate Remediation Code"
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
                    marginBottom: 10,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Sparkles size={14} style={{ color: "var(--accent)" }} />
                    <span
                      className="font-mono"
                      style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.1em", textTransform: "uppercase" }}
                    >
                      Fix Code
                    </span>
                  </div>
                  <button
                    onClick={handleCopyCode}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 4,
                      padding: "4px 10px",
                      fontSize: 11,
                      fontFamily: "var(--font-mono)",
                      color: copied ? "var(--low)" : "var(--text-3)",
                      background: "transparent",
                      border: `1px solid ${copied ? "var(--low)" : "var(--border)"}`,
                      borderRadius: 4,
                      cursor: "pointer",
                      transition: "all var(--duration-fast)",
                    }}
                  >
                    {copied ? <Check size={11} /> : <Copy size={11} />}
                    {copied ? "Copied!" : "Copy"}
                  </button>
                </div>

                <pre
                  style={{
                    background: "var(--bg)",
                    color: "var(--accent)",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    lineHeight: 1.7,
                    padding: 16,
                    borderRadius: 8,
                    overflowX: "auto",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    margin: 0,
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

          {/* Source + timestamp */}
          <div
            className="font-mono"
            style={{
              marginTop: 20,
              padding: "12px 0",
              borderTop: "1px solid var(--border)",
              display: "flex",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 8,
              fontSize: 11,
              color: "var(--text-3)",
            }}
          >
            <span>
              Source: <span style={{ color: "var(--text-2)" }}>{finding.source || "engine"}</span>
              {finding.port && (
                <> &nbsp;·&nbsp; Port: <span style={{ color: "var(--text-2)" }}>{finding.port}</span></>
              )}
            </span>
            <span>
              Detected:{" "}
              {finding.timestamp
                ? new Date(finding.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
                : "—"}
            </span>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Shimmer loading placeholder ──────────────────────────────────────
function ShimmerBlock() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {[100, 85, 60].map((w, i) => (
        <div
          key={i}
          style={{
            width: `${w}%`,
            height: 14,
            borderRadius: 6,
            background: "linear-gradient(90deg, rgba(77,179,126,0.06) 25%, rgba(77,179,126,0.15) 50%, rgba(77,179,126,0.06) 75%)",
            backgroundSize: "200% 100%",
            animation: "shimmer 1.5s infinite linear",
          }}
        />
      ))}
      <style>{`
        @keyframes shimmer {
          0% { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>
    </div>
  );
}

function DrawerSection({ title, children }) {
  return (
    <div style={{ marginBottom: 22 }}>
      <h4
        className="font-mono"
        style={{
          fontSize: 10,
          color: "var(--text-3)",
          textTransform: "uppercase",
          letterSpacing: "0.15em",
          marginBottom: 10,
          paddingBottom: 6,
          borderBottom: "1px solid var(--border)",
        }}
      >
        {title}
      </h4>
      {children}
    </div>
  );
}

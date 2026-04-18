import React, { useState } from "react";
import { Globe, ArrowRight, Zap, Lock, Globe2 } from "lucide-react";
import { parseDomain, isValidDomain } from "../utils/domainParser";

const SUGGESTIONS = ["google.com", "github.com", "tesla.com"];

const FEATURES = [
  { icon: <Zap size={14} />, text: "Passive only" },
  { icon: <Lock size={14} />, text: "No auth required" },
  { icon: <Globe2 size={14} />, text: "Public sources only" },
];

export default function LandingPage({ onStartScan }) {
  const [input, setInput] = useState("");
  const [focused, setFocused] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    const domain = parseDomain(input);
    if (!isValidDomain(domain)) {
      setError("Enter a valid domain (e.g. example.com)");
      return;
    }
    setError("");
    onStartScan(domain);
  };

  const handleSuggestion = (domain) => {
    setInput(domain);
    setError("");
    onStartScan(domain);
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "0 20px",
        paddingTop: 56,
        background: `radial-gradient(ellipse 800px 600px at 50% 40%, rgba(0,255,178,0.04) 0%, transparent 70%)`,
      }}
    >
      {/* Hero */}
      <div
        style={{
          textAlign: "center",
          maxWidth: 560,
          width: "100%",
          animation: "fadeUp 0.6s var(--ease-sharp) both",
        }}
      >
        <h1
          className="font-display"
          style={{
            fontSize: "clamp(3rem, 8vw, 5rem)",
            fontWeight: 800,
            color: "var(--text-primary)",
            lineHeight: 1.1,
            marginBottom: 12,
          }}
        >
          NETMAP
        </h1>
        <p
          className="font-mono"
          style={{
            fontSize: "var(--text-sm)",
            color: "var(--accent)",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            marginBottom: 40,
          }}
        >
          Attack Surface. Exposed.
        </p>
      </div>

      {/* Input Card */}
      <div
        style={{
          maxWidth: 560,
          width: "100%",
          background: "var(--bg-surface)",
          border: focused
            ? "1px solid var(--accent)"
            : "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-xl)",
          padding: 32,
          boxShadow: focused
            ? "0 0 60px rgba(0,255,178,0.1)"
            : "0 0 60px rgba(0,255,178,0.05)",
          transition: "all var(--duration-base) var(--ease-smooth)",
          animation: "fadeUp 0.6s var(--ease-sharp) 0.2s both",
        }}
      >
        <form
          onSubmit={handleSubmit}
          style={{ display: "flex", gap: 12 }}
        >
          <div
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              gap: 10,
              background: "var(--bg-elevated)",
              borderRadius: "var(--radius-md)",
              padding: "0 14px",
              border: "1px solid var(--border-subtle)",
            }}
          >
            <Globe
              size={16}
              style={{ color: "var(--text-muted)", flexShrink: 0 }}
            />
            <input
              type="text"
              value={input}
              onChange={(e) => {
                setInput(e.target.value);
                if (error) setError("");
              }}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              placeholder="example.com"
              id="domain-input"
              style={{
                flex: 1,
                background: "transparent",
                border: "none",
                outline: "none",
                color: "var(--text-primary)",
                fontFamily: "var(--font-body)",
                fontSize: "var(--text-base)",
                padding: "12px 0",
              }}
              autoComplete="off"
              spellCheck="false"
            />
          </div>
          <button
            type="submit"
            id="start-scan-btn"
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "12px 20px",
              fontSize: "var(--text-sm)",
              fontFamily: "var(--font-body)",
              fontWeight: 500,
              color: "var(--accent)",
              background: "var(--accent-dim)",
              border: "1px solid var(--accent)",
              borderRadius: "var(--radius-md)",
              cursor: "pointer",
              whiteSpace: "nowrap",
              transition: "all var(--duration-base) var(--ease-smooth)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "var(--accent)";
              e.currentTarget.style.color = "#0B0F17";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "var(--accent-dim)";
              e.currentTarget.style.color = "var(--accent)";
            }}
          >
            Start Scan
            <ArrowRight size={16} />
          </button>
        </form>

        {error && (
          <p
            style={{
              marginTop: 10,
              fontSize: "var(--text-xs)",
              color: "var(--critical)",
              fontFamily: "var(--font-body)",
            }}
          >
            {error}
          </p>
        )}

        {/* Quick Suggestions */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginTop: 20,
            flexWrap: "wrap",
          }}
        >
          <span
            style={{
              fontSize: "var(--text-xs)",
              color: "var(--text-muted)",
              fontFamily: "var(--font-body)",
            }}
          >
            Try:
          </span>
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              onClick={() => handleSuggestion(s)}
              style={{
                padding: "5px 12px",
                fontSize: "var(--text-xs)",
                fontFamily: "var(--font-body)",
                color: "var(--text-muted)",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-md)",
                cursor: "pointer",
                transition: "all var(--duration-fast) var(--ease-smooth)",
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
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Feature Pills */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 20,
          marginTop: 32,
          flexWrap: "wrap",
          justifyContent: "center",
          animation: "fadeUp 0.6s var(--ease-sharp) 0.4s both",
        }}
      >
        {FEATURES.map((f, i) => (
          <span
            key={i}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontSize: "var(--text-xs)",
              color: "var(--text-muted)",
              fontFamily: "var(--font-body)",
            }}
          >
            {f.icon}
            {f.text}
          </span>
        ))}
      </div>
    </div>
  );
}

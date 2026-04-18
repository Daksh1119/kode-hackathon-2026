import React, { useState } from "react";
import { Download, Copy, Check } from "lucide-react";

export default function ExportSection({ onDownload, onCopy }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const success = await onCopy();
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div
      style={{
        maxWidth: "var(--max-width)",
        margin: "0 auto",
        padding: "48px 24px",
        display: "flex",
        justifyContent: "center",
        gap: 16,
        borderTop: "1px solid var(--border-subtle)",
      }}
    >
      <button
        onClick={onDownload}
        id="download-report-btn"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "12px 24px",
          fontSize: "var(--text-sm)",
          fontFamily: "var(--font-body)",
          fontWeight: 500,
          color: "#0B0F17",
          background: "var(--accent)",
          border: "1px solid var(--accent)",
          borderRadius: "var(--radius-md)",
          cursor: "pointer",
          transition: "all var(--duration-base) var(--ease-smooth)",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.opacity = "0.9";
          e.currentTarget.style.transform = "translateY(-1px)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.opacity = "1";
          e.currentTarget.style.transform = "translateY(0)";
        }}
      >
        <Download size={16} />
        Download Report (.txt)
      </button>

      <button
        onClick={handleCopy}
        id="copy-summary-btn"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "12px 24px",
          fontSize: "var(--text-sm)",
          fontFamily: "var(--font-body)",
          fontWeight: 500,
          color: copied ? "var(--low)" : "var(--accent)",
          background: "transparent",
          border: `1px solid ${copied ? "var(--low)" : "var(--accent)"}`,
          borderRadius: "var(--radius-md)",
          cursor: "pointer",
          transition: "all var(--duration-base) var(--ease-smooth)",
        }}
        onMouseEnter={(e) => {
          if (!copied) {
            e.currentTarget.style.background = "var(--accent)";
            e.currentTarget.style.color = "#0B0F17";
          }
        }}
        onMouseLeave={(e) => {
          if (!copied) {
            e.currentTarget.style.background = "transparent";
            e.currentTarget.style.color = "var(--accent)";
          }
        }}
      >
        {copied ? <Check size={16} /> : <Copy size={16} />}
        {copied ? "Copied!" : "Copy Summary to Clipboard"}
      </button>
    </div>
  );
}

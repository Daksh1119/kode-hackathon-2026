import React, { useState } from "react";
import SummaryCards from "./SummaryCards";
import AttackGraph from "./AttackGraph";
import FindingsTable from "./FindingsTable";
import DecisionPanel from "./DecisionPanel";
import SideNav from "./SideNav";
import { OpenPortsPanel, CloudIssuesPanel, HiddenFilesPanel, LogsPanel, SensitiveFilesPanel } from "./TabPanels";
import { countBySeverity } from "../../utils/severityHelpers";
import { Download, Copy, Check } from "lucide-react";

export default function Dashboard({
  findings,
  domain,
  activeFilter,
  onFilterChange,
  searchQuery,
  onSearchChange,
  onFindingClick,
  onDownload,
  onCopy,
  logs,
}) {
  const [activeTab, setActiveTab] = useState("attack");
  const [isCollapsed, setIsCollapsed] = useState(false);

  const renderMainContent = () => {
    switch (activeTab) {
      case "attack":
        return (
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            <AttackGraph findings={findings} domain={domain} onNodeClick={onFindingClick} />
            <FindingsTable
              findings={findings}
              activeFilter={activeFilter}
              onFilterChange={onFilterChange}
              searchQuery={searchQuery}
              onSearchChange={onSearchChange}
              onFindingClick={onFindingClick}
            />
          </div>
        );
      case "ports":
        return <OpenPortsPanel findings={findings} onFindingClick={onFindingClick} />;
      case "cloud":
        return <CloudIssuesPanel findings={findings} onFindingClick={onFindingClick} />;
      case "hidden":
        return <HiddenFilesPanel findings={findings} onFindingClick={onFindingClick} />;
      case "files":
        return <SensitiveFilesPanel findings={findings} onFindingClick={onFindingClick} />;
      case "logs":
        return <LogsPanel logs={logs || []} />;
      default:
        return null;
    }
  };

  return (
    <div
      style={{
        paddingTop: 56,
        paddingLeft: isCollapsed ? 68 : 220,
        transition: "padding-left var(--duration-base) var(--ease-smooth)",
        animation: "fadeIn 0.5s var(--ease-smooth)",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        position: "relative",
      }}
    >
      <SideNav
        activeTab={activeTab}
        onTabChange={setActiveTab}
        findings={findings}
        logs={logs || []}
        isCollapsed={isCollapsed}
        onToggle={() => setIsCollapsed(!isCollapsed)}
      />

      <div
        style={{
          width: "100%",
          maxWidth: "var(--max-width)",
          margin: "0 auto",
          padding: "24px 32px",
          position: "relative",
          zIndex: 1,
        }}
      >
        {/* Summary Cards */}
        <SummaryCards
          findings={findings}
          activeFilter={activeFilter}
          onFilterChange={onFilterChange}
        />

        {/* 2-column layout (Sidebar is now fixed, out of flow) */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 300px",
            gap: 24,
            marginTop: 24,
            alignItems: "start",
          }}
        >

          {/* Col 2 — Content (animated on tab switch) */}
          <div
            key={activeTab}
            style={{ animation: "tabFadeIn 0.22s var(--ease-smooth)", minWidth: 0 }}
          >
            {renderMainContent()}
          </div>

          {/* Col 3 — Right panel */}
          {activeTab === "attack" ? (
            <DecisionPanel
              findings={findings}
              onFindingClick={onFindingClick}
              onDownload={onDownload}
              onCopy={onCopy}
            />
          ) : (
            <MiniPanel findings={findings} onDownload={onDownload} onCopy={onCopy} />
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Compact Summary Panel (non-attack tabs) ─────────────────────── */
function MiniPanel({ findings, onDownload, onCopy }) {
  const [copied, setCopied] = useState(false);
  const counts = countBySeverity(findings);

  const handleCopy = async () => {
    const ok = await onCopy();
    if (ok) { setCopied(true); setTimeout(() => setCopied(false), 2000); }
  };

  const rows = [
    { key: "critical", label: "Critical", color: "#FF3B5C", bg: "rgba(255,59,92,0.1)"   },
    { key: "high",     label: "High",     color: "#FF7043", bg: "rgba(255,112,67,0.1)"  },
    { key: "medium",   label: "Medium",   color: "#FFB300", bg: "rgba(255,179,0,0.1)"   },
    { key: "low",      label: "Low",      color: "#00E5FF", bg: "rgba(0,229,255,0.08)" },
  ];

  return (
    <div
      style={{
        position: "sticky",
        top: 80,
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 14,
        padding: "20px",
        display: "flex",
        flexDirection: "column",
        gap: 14,
      }}
    >
      <h3
        className="font-mono"
        style={{ fontSize: 10, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.14em" }}
      >
        Summary
      </h3>

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {rows.map(({ key, label, color, bg }) =>
          counts[key] > 0 ? (
            <div
              key={key}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "7px 12px",
                borderRadius: 9,
                background: bg,
                border: `1px solid ${color}28`,
              }}
            >
              <span style={{ fontSize: 12, color, fontWeight: 600, fontFamily: "var(--font-body)" }}>
                ● {label}
              </span>
              <span className="font-mono" style={{ fontSize: 14, fontWeight: 700, color }}>
                {counts[key]}
              </span>
            </div>
          ) : null
        )}
      </div>

      <div
        style={{
          padding: "10px 0",
          borderTop: "1px solid var(--border)",
          fontSize: 12,
          color: "var(--text-3)",
          fontFamily: "var(--font-body)",
        }}
      >
        <span style={{ color: "var(--text)", fontWeight: 600 }}>{findings.length}</span> total findings
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <button
          onClick={handleCopy}
          style={{
            display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
            padding: "9px 10px", fontSize: 12, fontFamily: "var(--font-display)", fontWeight: 600,
            color: copied ? "var(--green-accent)" : "var(--accent)",
            background: "transparent",
            border: `1px solid ${copied ? "var(--green-accent)" : "var(--accent)"}`,
            borderRadius: 9, cursor: "pointer", transition: "all var(--duration-base)",
          }}
        >
          {copied ? <Check size={13} /> : <Copy size={13} />}
          {copied ? "Copied!" : "Copy Summary"}
        </button>
        <button
          onClick={onDownload}
          style={{
            display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
            padding: "9px 10px", fontSize: 12, fontFamily: "var(--font-display)", fontWeight: 600,
            color: "#0A0E1A", background: "var(--accent)", border: "1px solid var(--accent)",
            borderRadius: 9, cursor: "pointer", transition: "all var(--duration-base)",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.88")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
        >
          <Download size={13} />
          Download Report
        </button>
      </div>
    </div>
  );
}

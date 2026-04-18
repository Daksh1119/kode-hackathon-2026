import React, { useMemo } from "react";
import { ChevronRight, Globe, Lock, Unlock, AlertTriangle, Info, Cloud, FolderOpen, Terminal, FileWarning, Key } from "lucide-react";
import { SEVERITY_CONFIG } from "../../utils/severityHelpers";

// ─── Severity pill ──────────────────────────────────────────────────────
function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || {};
  const colorMap = {
    critical: { color: "#FF3B5C", bg: "rgba(255,59,92,0.12)" },
    high:     { color: "#FF7043", bg: "rgba(255,112,67,0.12)" },
    medium:   { color: "#FFB300", bg: "rgba(255,179,0,0.12)" },
    low:      { color: "#4DB37E", bg: "rgba(77,179,126,0.1)" },
    info:     { color: "#448AFF", bg: "rgba(68,138,255,0.12)" },
  };
  const s = colorMap[severity] || { color: "var(--text-3)", bg: "var(--elevated)" };

  return (
    <span
      className="font-mono"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        padding: "2px 9px",
        borderRadius: 999,
        fontSize: 10,
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.07em",
        color: s.color,
        background: s.bg,
        flexShrink: 0,
      }}
    >
      ● {severity}
    </span>
  );
}

// ─── Open Ports Panel ──────────────────────────────────────────────────
export function OpenPortsPanel({ findings, onFindingClick }) {
  const portFindings = useMemo(
    () =>
      findings
        .filter((f) => f.port != null || f.source === "nmap")
        .sort((a, b) => {
          const sev = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (sev[a.severity] ?? 5) - (sev[b.severity] ?? 5);
        }),
    [findings]
  );

  const SERVICE_COLORS = {
    21: { label: "FTP", color: "#FF7043" },
    22: { label: "SSH", color: "#4DB37E" },
    25: { label: "SMTP", color: "#FFB300" },
    80: { label: "HTTP", color: "#448AFF" },
    443: { label: "HTTPS", color: "#4DD0E1" },
    3389: { label: "RDP", color: "#FF3B5C" },
    8080: { label: "HTTP-Alt", color: "#448AFF" },
    8443: { label: "HTTPS-Alt", color: "#4DD0E1" },
    135: { label: "RPC", color: "#CE93D8" },
  };

  const getService = (port) => SERVICE_COLORS[port] || { label: `Port ${port}`, color: "var(--text-3)" };

  return (
    <SectionWrapper
      icon={<Globe size={16} style={{ color: "var(--green-accent)" }} />}
      title="Open Ports"
      count={portFindings.length}
      description="Network ports exposed and reachable from the internet"
    >
      {portFindings.length === 0 ? (
        <EmptyState icon="⬡" message="No open port findings detected" />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {portFindings.map((f) => {
            const svc = getService(f.port);
            return (
              <FindingCard
                key={f.id}
                finding={f}
                onClick={() => onFindingClick(f)}
                leftSlot={
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      gap: 2,
                      minWidth: 54,
                    }}
                  >
                    <span
                      className="font-mono"
                      style={{ fontSize: 18, fontWeight: 700, color: svc.color, lineHeight: 1 }}
                    >
                      {f.port ?? "—"}
                    </span>
                    <span
                      className="font-mono"
                      style={{
                        fontSize: 9,
                        color: svc.color,
                        background: `${svc.color}18`,
                        padding: "1px 6px",
                        borderRadius: 4,
                        textTransform: "uppercase",
                        letterSpacing: "0.07em",
                      }}
                    >
                      {svc.label}
                    </span>
                  </div>
                }
              />
            );
          })}
        </div>
      )}
    </SectionWrapper>
  );
}

// ─── Cloud Issues Panel ────────────────────────────────────────────────
export function CloudIssuesPanel({ findings, onFindingClick }) {
  const cloudFindings = useMemo(
    () =>
      findings
        .filter((f) => f.source === "cloud")
        .sort((a, b) => {
          const sev = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (sev[a.severity] ?? 5) - (sev[b.severity] ?? 5);
        }),
    [findings]
  );

  return (
    <SectionWrapper
      icon={<Cloud size={16} style={{ color: "var(--green-accent)" }} />}
      title="Cloud Issues"
      count={cloudFindings.length}
      description="Publicly accessible cloud storage buckets, misconfigurations, and exposed resources"
    >
      {cloudFindings.length === 0 ? (
        <EmptyState icon="☁" message="No cloud misconfigurations detected" />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {cloudFindings.map((f) => {
            const isUnlocked = f.severity === "high" || f.severity === "critical";
            return (
              <FindingCard
                key={f.id}
                finding={f}
                onClick={() => onFindingClick(f)}
                leftSlot={
                  <div
                    style={{
                      width: 40,
                      height: 40,
                      borderRadius: 10,
                      background: isUnlocked
                        ? "rgba(255,112,67,0.1)"
                        : "rgba(77,179,126,0.1)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    {isUnlocked ? (
                      <Unlock size={16} style={{ color: "var(--high)" }} />
                    ) : (
                      <Lock size={16} style={{ color: "var(--green-accent)" }} />
                    )}
                  </div>
                }
              />
            );
          })}
        </div>
      )}
    </SectionWrapper>
  );
}

// ─── Hidden Files Panel ─────────────────────────────────────────────────
export function HiddenFilesPanel({ findings, onFindingClick }) {
  const hiddenFindings = useMemo(
    () =>
      findings
        .filter(
          (f) =>
            f.source === "engine" ||
            f.title?.toLowerCase().includes("hidden") ||
            f.title?.toLowerCase().includes("director") ||
            f.title?.toLowerCase().includes("admin") ||
            f.title?.toLowerCase().includes("panel") ||
            f.title?.toLowerCase().includes("backup") ||
            f.title?.toLowerCase().includes("config")
        )
        .sort((a, b) => {
          const sev = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (sev[a.severity] ?? 5) - (sev[b.severity] ?? 5);
        }),
    [findings]
  );

  return (
    <SectionWrapper
      icon={<FolderOpen size={16} style={{ color: "var(--green-accent)" }} />}
      title="Hidden Files & Directories"
      count={hiddenFindings.length}
      description="Exposed admin panels, config files, backups, and directory listings"
    >
      {hiddenFindings.length === 0 ? (
        <EmptyState icon="◎" message="No hidden files or directories detected" />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {hiddenFindings.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              onClick={() => onFindingClick(f)}
              leftSlot={
                <div
                  style={{
                    width: 40,
                    height: 40,
                    borderRadius: 10,
                    background: "rgba(77,179,126,0.08)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <FolderOpen size={15} style={{ color: "var(--green-accent)" }} />
                </div>
              }
            />
          ))}
        </div>
      )}
    </SectionWrapper>
  );
}
// ─── Sensitive Files Panel ──────────────────────────────────────────────
export function SensitiveFilesPanel({ findings, onFindingClick }) {
  const fileFindings = useMemo(
    () =>
      findings
        .filter((f) => f.source === "file_scanner")
        .sort((a, b) => {
          const sev = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (sev[a.severity] ?? 5) - (sev[b.severity] ?? 5);
        }),
    [findings]
  );

  return (
    <SectionWrapper
      icon={<FileWarning size={16} style={{ color: "var(--critical)" }} />}
      title="Sensitive Files & Backups"
      count={fileFindings.length}
      description="Publicly exposed internal configuration files, credentials, logs, and database dumps."
    >
      {fileFindings.length === 0 ? (
        <EmptyState icon="🔐" message="No sensitive files detected" />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {fileFindings.map((f) => {
            const hasSecrets = f.exposed_secrets && f.exposed_secrets.length > 0;
            return (
              <FindingCard
                key={f.id}
                finding={f}
                onClick={() => onFindingClick(f)}
                leftSlot={
                  <div
                    style={{
                      width: 40,
                      height: 40,
                      borderRadius: 10,
                      background: hasSecrets ? "rgba(255, 59, 92, 0.12)" : "rgba(255, 179, 0, 0.1)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    {hasSecrets ? (
                      <Key size={15} style={{ color: "var(--critical)" }} />
                    ) : (
                      <FileWarning size={15} style={{ color: "var(--medium)" }} />
                    )}
                  </div>
                }
              />
            );
          })}
        </div>
      )}
    </SectionWrapper>
  );
}


// ─── Logs Panel ────────────────────────────────────────────────────────
const LOG_COLORS = {
  info:  "var(--accent)",
  found: "var(--green-accent)",
  warn:  "var(--medium)",
  error: "var(--critical)",
};
const LOG_PREFIX = {
  info:  "[+]",
  found: "[✓]",
  warn:  "[!]",
  error: "[✗]",
};

export function LogsPanel({ logs }) {
  const containerRef = React.useRef(null);

  React.useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <SectionWrapper
      icon={<Terminal size={16} style={{ color: "var(--green-accent)" }} />}
      title="Logs"
      count={logs?.length || 0}
      description="Raw scan output and diagnostic messages from the reconnaissance pipeline"
    >
      <div
        ref={containerRef}
        style={{
          background: "#0a0a0a",
          borderRadius: 10,
          border: "1px solid rgba(77,179,126,0.12)",
          padding: "16px 20px",
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          lineHeight: 1.8,
          maxHeight: "calc(100vh - 340px)",
          overflowY: "auto",
          color: "#ccc",
        }}
      >
        {/* Mac traffic lights header */}
        <div
          style={{
            display: "flex",
            gap: 7,
            marginBottom: 14,
            paddingBottom: 12,
            borderBottom: "1px solid rgba(255,255,255,0.06)",
          }}
        >
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#FF5F56" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#FFBD2E" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#27C93F" }} />
          <span
            style={{
              marginLeft: "auto",
              fontSize: 10,
              color: "#555",
              letterSpacing: "0.05em",
            }}
          >
            bash — scan_log
          </span>
        </div>

        {!logs || logs.length === 0 ? (
          <div style={{ color: "#444", textAlign: "center", padding: "24px 0" }}>
            No logs available
          </div>
        ) : (
          logs.map((log, i) => (
            <div key={log.id || i} style={{ display: "flex", gap: 12, marginBottom: 2 }}>
              <span style={{ color: "#444", flexShrink: 0, minWidth: 70 }}>
                {log.timestamp}
              </span>
              <span
                style={{
                  color: LOG_COLORS[log.type] || "var(--accent)",
                  flexShrink: 0,
                  fontWeight: 600,
                  minWidth: 28,
                }}
              >
                {LOG_PREFIX[log.type] || "[+]"}
              </span>
              <span
                style={{
                  color:
                    log.type === "error"
                      ? "#FF5F56"
                      : log.type === "warn"
                      ? "#FFBD2E"
                      : log.type === "found"
                      ? "#4DB37E"
                      : "#ddd",
                  wordBreak: "break-word",
                  whiteSpace: "pre-wrap",
                }}
              >
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>
    </SectionWrapper>
  );
}

// ─── Shared: FindingCard ──────────────────────────────────────────────
function FindingCard({ finding, onClick, leftSlot }) {
  return (
    <div
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 14,
        padding: "14px 16px",
        background: "var(--elevated)",
        borderRadius: 12,
        border: "1px solid var(--border)",
        cursor: "pointer",
        transition: "all 150ms var(--ease-smooth)",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = "rgba(255,255,255,0.04)";
        e.currentTarget.style.borderColor = "var(--border-hover)";
        e.currentTarget.querySelector(".card-arrow").style.opacity = "1";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "var(--elevated)";
        e.currentTarget.style.borderColor = "var(--border)";
        e.currentTarget.querySelector(".card-arrow").style.opacity = "0";
      }}
    >
      {leftSlot}

      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: 13,
            fontWeight: 500,
            color: "var(--text)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            marginBottom: 4,
            fontFamily: "var(--font-body)",
          }}
        >
          {finding.title}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <SeverityBadge severity={finding.severity} />
          <span
            className="font-mono"
            style={{ fontSize: 11, color: "var(--accent)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 160 }}
          >
            {finding.host}
          </span>
          {finding.source && (
            <span
              className={`source-badge source-${finding.source}`}
              style={{ flexShrink: 0 }}
            >
              {finding.source}
            </span>
          )}
        </div>
        {finding.action && (
          <div
            style={{
              fontSize: 11,
              color: "var(--text-3)",
              marginTop: 5,
              fontFamily: "var(--font-body)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {finding.action}
          </div>
        )}
      </div>

      <ChevronRight
        className="card-arrow"
        size={15}
        style={{ color: "var(--green-accent)", opacity: 0, transition: "opacity 150ms", flexShrink: 0 }}
      />
    </div>
  );
}

// ─── Shared: SectionWrapper ────────────────────────────────────────────
function SectionWrapper({ icon, title, count, description, children }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Panel header */}
      <div
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: 12,
          padding: "18px 20px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
          {icon}
          <h2
            className="font-display"
            style={{ fontSize: 16, fontWeight: 600, color: "var(--text)", flex: 1 }}
          >
            {title}
          </h2>
          {count != null && (
            <span
              className="font-mono"
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: "var(--green-accent)",
                background: "var(--green-accent-dim)",
                padding: "2px 10px",
                borderRadius: 999,
              }}
            >
              {count}
            </span>
          )}
        </div>
        <p style={{ fontSize: 13, color: "var(--text-3)", fontFamily: "var(--font-body)", lineHeight: 1.5 }}>
          {description}
        </p>
      </div>

      {children}
    </div>
  );
}

// ─── Shared: EmptyState ────────────────────────────────────────────────
function EmptyState({ icon, message }) {
  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 12,
        padding: "48px 24px",
        textAlign: "center",
      }}
    >
      <div style={{ fontSize: "2.2rem", marginBottom: 12, opacity: 0.4 }}>{icon}</div>
      <div
        style={{
          fontSize: 14,
          color: "var(--text-3)",
          fontFamily: "var(--font-body)",
        }}
      >
        {message}
      </div>
    </div>
  );
}

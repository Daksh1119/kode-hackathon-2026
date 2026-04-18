import React, { useMemo } from "react";
import { Search, ChevronRight, Circle } from "lucide-react";
import { sortBySeverity, SEVERITY_CONFIG } from "../../utils/severityHelpers";

const FILTER_OPTIONS = ["all", "critical", "high", "medium", "low"];

export default function FindingsTable({
  findings,
  activeFilter,
  onFilterChange,
  searchQuery,
  onSearchChange,
  onFindingClick,
}) {
  // Filter and search
  const filtered = useMemo(() => {
    let result = findings;

    if (activeFilter !== "all") {
      result = result.filter((f) => f.severity === activeFilter);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.host.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q)
      );
    }

    return sortBySeverity(result);
  }, [findings, activeFilter, searchQuery]);

  return (
    <div
      style={{
        background: "var(--bg-surface)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "var(--radius-lg)",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "20px 24px",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 16,
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <h3
            className="font-mono"
            style={{
              fontSize: "var(--text-xs)",
              color: "var(--text-muted)",
              textTransform: "uppercase",
              letterSpacing: "0.15em",
            }}
          >
            Findings ({filtered.length})
          </h3>

          {/* Search */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              background: "var(--bg-elevated)",
              borderRadius: "var(--radius-md)",
              padding: "6px 12px",
              border: "1px solid var(--border-subtle)",
              minWidth: 220,
            }}
          >
            <Search size={14} style={{ color: "var(--text-muted)" }} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search hosts, issues..."
              id="findings-search"
              style={{
                flex: 1,
                background: "transparent",
                border: "none",
                outline: "none",
                color: "var(--text-primary)",
                fontFamily: "var(--font-body)",
                fontSize: "var(--text-xs)",
              }}
            />
          </div>
        </div>

        {/* Filter Pills */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {FILTER_OPTIONS.map((filter) => {
            const isActive = activeFilter === filter;
            const config =
              filter === "all"
                ? { label: "All", color: "var(--text-secondary)" }
                : {
                    label: SEVERITY_CONFIG[filter].label,
                    color: SEVERITY_CONFIG[filter].color,
                  };

            return (
              <button
                key={filter}
                onClick={() => onFilterChange(filter)}
                style={{
                  padding: "4px 12px",
                  fontSize: "var(--text-xs)",
                  fontFamily: "var(--font-body)",
                  color: isActive ? config.color : "var(--text-muted)",
                  background: isActive
                    ? filter === "all"
                      ? "var(--bg-elevated)"
                      : SEVERITY_CONFIG[filter]?.bg || "var(--bg-elevated)"
                    : "transparent",
                  border: isActive
                    ? `1px solid ${config.color}`
                    : "1px solid var(--border-subtle)",
                  borderRadius: "var(--radius-md)",
                  cursor: "pointer",
                  transition: "all var(--duration-fast)",
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.borderColor = "var(--border-active)";
                    e.currentTarget.style.color = "var(--text-secondary)";
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.borderColor = "var(--border-subtle)";
                    e.currentTarget.style.color = "var(--text-muted)";
                  }
                }}
              >
                {config.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Table */}
      <div style={{ overflowX: "auto" }}>
        {/* Table Header */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "140px 1fr 200px 1fr 40px",
            padding: "10px 24px",
            fontSize: "var(--text-xs)",
            color: "var(--text-muted)",
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            fontFamily: "var(--font-body)",
            borderBottom: "1px solid var(--border-subtle)",
          }}
        >
          <span>Severity</span>
          <span>Issue</span>
          <span>Host</span>
          <span>Action</span>
          <span></span>
        </div>

        {/* Rows */}
        {filtered.length > 0 ? (
          filtered.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              onClick={() => onFindingClick(finding)}
            />
          ))
        ) : (
          <div
            style={{
              textAlign: "center",
              padding: "48px 24px",
              color: "var(--text-muted)",
            }}
          >
            <div style={{ fontSize: "2rem", marginBottom: 12 }}>◎</div>
            <div style={{ fontSize: "var(--text-sm)" }}>
              No findings match
            </div>
            <div style={{ fontSize: "var(--text-sm)" }}>
              your current filter.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function FindingRow({ finding, onClick }) {
  const config = SEVERITY_CONFIG[finding.severity];

  return (
    <div
      onClick={onClick}
      style={{
        display: "grid",
        gridTemplateColumns: "140px 1fr 200px 1fr 40px",
        padding: "14px 24px",
        alignItems: "center",
        borderBottom: "1px solid var(--border-subtle)",
        cursor: "pointer",
        transition: "background var(--duration-fast)",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = "var(--bg-elevated)";
        const arrow = e.currentTarget.querySelector(".row-arrow");
        if (arrow) arrow.style.opacity = "1";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "transparent";
        const arrow = e.currentTarget.querySelector(".row-arrow");
        if (arrow) arrow.style.opacity = "0";
      }}
    >
      {/* Severity Badge */}
      <div>
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
      </div>

      {/* Issue Title */}
      <span
        style={{
          fontSize: "var(--text-sm)",
          color: "var(--text-primary)",
          fontWeight: 500,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          paddingRight: 12,
        }}
      >
        {finding.title}
      </span>

      {/* Host */}
      <span
        className="font-mono"
        style={{
          fontSize: "var(--text-xs)",
          color: "var(--accent)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {finding.host}
      </span>

      {/* Action */}
      <span
        style={{
          fontSize: "var(--text-xs)",
          color: "var(--text-secondary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          paddingRight: 8,
        }}
      >
        {finding.action}
      </span>

      {/* Arrow */}
      <div
        className="row-arrow"
        style={{
          opacity: 0,
          transition: "opacity var(--duration-fast)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <ChevronRight
          size={16}
          style={{ color: "var(--text-secondary)" }}
        />
      </div>
    </div>
  );
}

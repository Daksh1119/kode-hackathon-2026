import React, { useMemo, useEffect, useRef } from "react";
import { Search, ChevronRight } from "lucide-react";
import { sortBySeverity, SEVERITY_CONFIG } from "../../utils/severityHelpers";

const FILTER_OPTIONS = ["all", "high", "medium", "low"];

const SOURCE_CLASS = {
  nmap:   "source-nmap",
  cloud:  "source-cloud",
  engine: "source-engine",
  nuclei: "source-nuclei",
  dns:    "source-dns",
};

export default function FindingsTable({
  findings,
  activeFilter,
  onFilterChange,
  searchQuery,
  onSearchChange,
  onFindingClick,
}) {
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
          f.description?.toLowerCase().includes(q)
      );
    }
    return sortBySeverity(result);
  }, [findings, activeFilter, searchQuery]);

  // IntersectionObserver for scroll-triggered row reveal
  const rowRefs = useRef([]);
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            observer.unobserve(e.target);
          }
        });
      },
      { threshold: 0.1 }
    );
    rowRefs.current.forEach((row) => {
      if (row) observer.observe(row);
    });
    return () => observer.disconnect();
  }, [filtered]);

  const getFilterLabel = (f) => {
    if (f === "all") return `ALL`;
    const count = findings.filter((x) => x.severity === f).length;
    return `${f.toUpperCase()} ${count}`;
  };

  const getFilterColor = (f) => {
    if (f === "all") return "var(--text-2)";
    return SEVERITY_CONFIG[f]?.color || "var(--text-2)";
  };

  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 10,
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "20px 24px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 14,
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <h3
            className="font-display"
            style={{
              fontSize: 16,
              fontWeight: 600,
              color: "var(--text)",
            }}
          >
            FINDINGS ({filtered.length})
          </h3>

          {/* Search */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              background: "var(--elevated)",
              borderRadius: 8,
              padding: "6px 12px",
              border: "1px solid var(--border)",
              minWidth: 220,
            }}
          >
            <Search size={13} style={{ color: "var(--text-3)" }} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search hosts, issues..."
              id="findings-search"
              className="font-mono"
              style={{
                flex: 1,
                background: "transparent",
                border: "none",
                outline: "none",
                color: "var(--text)",
                fontSize: 12,
                fontFamily: "var(--font-mono)",
              }}
            />
          </div>
        </div>

        {/* Filter Pills */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {FILTER_OPTIONS.map((filter) => {
            const isActive = activeFilter === filter;
            const color = getFilterColor(filter);
            const bg = filter !== "all" && SEVERITY_CONFIG[filter]?.bg;
            return (
              <button
                key={filter}
                onClick={() => onFilterChange(filter)}
                className="font-mono"
                style={{
                  padding: "4px 14px",
                  fontSize: 11,
                  fontFamily: "var(--font-mono)",
                  color: isActive ? color : "var(--text-3)",
                  background: isActive ? (bg || "var(--elevated)") : "transparent",
                  border: isActive ? `1px solid ${color}` : "1px solid var(--border)",
                  borderRadius: 999,
                  cursor: "pointer",
                  transition: "all var(--duration-fast)",
                  letterSpacing: "0.06em",
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.borderColor = "var(--border-hover)";
                    e.currentTarget.style.color = "var(--text-2)";
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.borderColor = "var(--border)";
                    e.currentTarget.style.color = "var(--text-3)";
                  }
                }}
              >
                {getFilterLabel(filter)}
              </button>
            );
          })}
        </div>
      </div>

      {/* Table */}
      <div style={{ overflowX: "auto" }}>
        {/* Table header */}
        <div
          className="font-mono"
          style={{
            display: "grid",
            gridTemplateColumns: "110px 80px 1fr 170px 50px 80px 1fr 36px",
            padding: "10px 24px",
            fontSize: 10,
            color: "var(--text-3)",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <span>Severity</span>
          <span>Tier</span>
          <span>Issue</span>
          <span>Host</span>
          <span>Port</span>
          <span>Source</span>
          <span>Action</span>
          <span></span>
        </div>

        {/* Rows */}
        {filtered.length > 0 ? (
          filtered.map((finding, i) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              onClick={() => onFindingClick(finding)}
              rowRef={(el) => (rowRefs.current[i] = el)}
            />
          ))
        ) : (
          <div
            style={{
              textAlign: "center",
              padding: "48px 24px",
              color: "var(--text-3)",
            }}
          >
            <div style={{ fontSize: "2rem", marginBottom: 12 }}>◎</div>
            <div style={{ fontSize: 14, fontFamily: "var(--font-body)" }}>No findings match your current filter.</div>
          </div>
        )}
      </div>
    </div>
  );
}

function FindingRow({ finding, onClick, rowRef }) {
  const config = SEVERITY_CONFIG[finding.severity];

  return (
    <div
      ref={rowRef}
      onClick={onClick}
      className="table-row"
      style={{
        display: "grid",
        gridTemplateColumns: "110px 80px 1fr 170px 50px 80px 1fr 36px",
        padding: "14px 24px",
        alignItems: "center",
        borderBottom: "1px solid var(--border)",
        cursor: "pointer",
        transition: "background var(--duration-fast)",
        minHeight: 52,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = "var(--elevated)";
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
        <span className={`severity-badge ${(finding.severity || "low").toLowerCase()}`}>
          ● {finding.severity.toUpperCase()}
        </span>
      </div>

      {/* Priority Tier */}
      <div className="font-mono" style={{ fontSize: 12, fontWeight: 700 }}>
        {finding.priority_tier ? (
          <span style={{
            color: finding.priority_tier === "P0" ? "var(--high)" : 
                   finding.priority_tier === "P1" ? "var(--medium)" : "var(--low)"
          }}>
            {finding.priority_tier}
            <span style={{ color: "var(--text-3)", fontSize: 10, fontWeight: 400, marginLeft: 4 }}>
              {finding.priority_score}
            </span>
          </span>
        ) : (
          <span style={{ color: "var(--text-3)" }}>—</span>
        )}
      </div>

      {/* Issue Title */}
      <span
        className="font-display"
        style={{
          fontSize: 14,
          fontWeight: 500,
          color: "var(--text)",
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
          fontSize: 12,
          color: "var(--accent)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={finding.host}
      >
        {finding.host}
      </span>

      {/* Port */}
      <span
        className="font-mono"
        style={{
          fontSize: 13,
          color: "var(--text-2)",
        }}
      >
        {finding.port ?? "—"}
      </span>

      {/* Source */}
      <span className={`source-badge source-${finding.source || "engine"}`}>
        {finding.source || "engine"}
      </span>

      {/* Action */}
      <span
        style={{
          fontSize: 12,
          color: "var(--text-3)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          paddingRight: 8,
          fontFamily: "var(--font-body)",
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
        <ChevronRight size={16} style={{ color: "var(--accent)" }} />
      </div>
    </div>
  );
}

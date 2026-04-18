import React from "react";
import SummaryCards from "./SummaryCards";
import AttackGraph from "./AttackGraph";
import FindingsTable from "./FindingsTable";
import DecisionPanel from "./DecisionPanel";

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
}) {
  return (
    <div
      style={{
        paddingTop: 68,
        animation: "fadeIn 0.5s var(--ease-smooth)",
      }}
    >
      <div
        style={{
          maxWidth: "var(--max-width)",
          margin: "0 auto",
          padding: "24px",
        }}
      >
        {/* Summary Cards — Top Row */}
        <SummaryCards
          findings={findings}
          activeFilter={activeFilter}
          onFilterChange={onFilterChange}
        />

        {/* Main Content + Decision Panel */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 320px",
            gap: 24,
            marginTop: 24,
          }}
        >
          {/* Left — Main Content */}
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            {/* Attack Graph */}
            <AttackGraph
              findings={findings}
              domain={domain}
              onNodeClick={onFindingClick}
            />

            {/* Findings Table */}
            <FindingsTable
              findings={findings}
              activeFilter={activeFilter}
              onFilterChange={onFilterChange}
              searchQuery={searchQuery}
              onSearchChange={onSearchChange}
              onFindingClick={onFindingClick}
            />
          </div>

          {/* Right — Decision Panel */}
          <DecisionPanel
            findings={findings}
            onFindingClick={onFindingClick}
            onDownload={onDownload}
            onCopy={onCopy}
          />
        </div>
      </div>
    </div>
  );
}

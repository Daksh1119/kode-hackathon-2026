import React from "react";
import Navbar from "./components/Navbar";
import LandingPage from "./components/LandingPage";
import ScanScreen from "./components/ScanScreen";
import Dashboard from "./components/Dashboard";
import DetailDrawer from "./components/DetailDrawer";
import ExportSection from "./components/ExportSection";
import { useScan } from "./hooks/useScan";
import { useExport } from "./hooks/useExport";

export default function App() {
  const {
    domain,
    scanStatus,
    progress,
    logs,
    findings,
    selectedFinding,
    activeFilter,
    searchQuery,
    stageStates,
    elapsed,
    subsFound,
    startScan,
    resetScan,
    setSelectedFinding,
    setActiveFilter,
    setSearchQuery,
  } = useScan();

  const { downloadReport, copySummary } = useExport(domain, findings);

  return (
    <div style={{ minHeight: "100vh" }}>
      <Navbar scanStatus={scanStatus} onNewScan={resetScan} />

      {/* === IDLE: Landing Page === */}
      {scanStatus === "idle" && <LandingPage onStartScan={startScan} />}

      {/* === RUNNING: Scan Screen === */}
      {scanStatus === "running" && (
        <ScanScreen
          progress={progress}
          logs={logs}
          stageStates={stageStates}
          domain={domain}
          elapsed={elapsed}
          subsFound={subsFound}
        />
      )}

      {/* === DONE: Dashboard + Export === */}
      {scanStatus === "done" && (
        <>
          <Dashboard
            findings={findings}
            domain={domain}
            activeFilter={activeFilter}
            onFilterChange={setActiveFilter}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            onFindingClick={setSelectedFinding}
            onDownload={downloadReport}
            onCopy={copySummary}
          />
          <ExportSection
            onDownload={downloadReport}
            onCopy={copySummary}
          />
        </>
      )}

      {/* === Detail Drawer (overlay) === */}
      {selectedFinding && (
        <DetailDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}

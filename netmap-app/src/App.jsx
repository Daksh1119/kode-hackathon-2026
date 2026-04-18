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
    hostsFound,
    openPortsFound,
    startScan,
    resetScan,
    setSelectedFinding,
    setActiveFilter,
    setSearchQuery,
  } = useScan();

  const { downloadReport, copySummary } = useExport(domain, findings);

  return (
    <div style={{ minHeight: "100vh" }}>
      {/* Navbar only during and after scan */}
      {scanStatus !== "idle" && <Navbar scanStatus={scanStatus} onNewScan={resetScan} />}

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
          hostsFound={hostsFound}
          openPortsFound={openPortsFound}
        />
      )}

      {/* === DONE: Dashboard + Export === */}
      {scanStatus === "done" && (
        <div
          style={{
            "--bg": "#050905",
            "--surface": "#000000",
            "--elevated": "#000000",
            "--sidenav-bg": "#000000",
            "--text": "#FFFFFF",
            "--text-primary": "#FFFFFF",
            "--border": "rgba(255,255,255,0.12)",
            "--accent": "#4DB37E",
            "--green-accent": "#4DB37E",
            "--green-accent-dim": "rgba(170, 255, 0, 0.12)",
            background: "radial-gradient(ellipse 700px 500px at 50% 45%, rgba(170,255,0,0.06) 0%, transparent 70%), #050905",
            backgroundAttachment: "fixed",
            minHeight: "100vh",
            position: "relative",
          }}
        >
          {/* Subtle green grid background */}
          <div
            style={{
              position: "fixed",
              inset: 0,
              backgroundImage: "linear-gradient(rgba(170,255,0,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(170,255,0,0.03) 1px, transparent 1px)",
              backgroundSize: "60px 60px",
              pointerEvents: "none",
              zIndex: 0,
            }}
          />
          <div style={{ position: "relative", zIndex: 1 }}>
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
              logs={logs}
            />
            <ExportSection
              onDownload={downloadReport}
              onCopy={copySummary}
            />
            {/* === Detail Drawer (overlay) as Popup === */}
            {selectedFinding && (
              <DetailDrawer
                finding={selectedFinding}
                onClose={() => setSelectedFinding(null)}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

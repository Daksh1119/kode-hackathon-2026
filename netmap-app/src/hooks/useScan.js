import { useState, useCallback, useRef } from "react";
import { DEMO_FINDINGS, DEMO_LOGS, SCAN_STAGES } from "../data/mockFindings";

/**
 * Custom hook that orchestrates the scan simulation.
 * Manages state transitions: idle → running → done
 * Simulates log streaming and stage progression.
 */
export function useScan() {
  const [domain, setDomain] = useState("");
  const [scanStatus, setScanStatus] = useState("idle"); // 'idle' | 'running' | 'done'
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeFilter, setActiveFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [stageStates, setStageStates] = useState(
    SCAN_STAGES.map(() => "pending")
  );
  const [startTime, setStartTime] = useState(null);
  const [elapsed, setElapsed] = useState("0:00:00");
  const [subsFound, setSubsFound] = useState(0);

  const timerRef = useRef(null);
  const scanRef = useRef(null);

  const formatTime = (ms) => {
    const secs = Math.floor(ms / 1000);
    const mins = Math.floor(secs / 60);
    const hours = Math.floor(mins / 60);
    return `${hours}:${String(mins % 60).padStart(2, "0")}:${String(secs % 60).padStart(2, "0")}`;
  };

  const getNow = () => {
    const d = new Date();
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  };

  const startScan = useCallback(
    (targetDomain) => {
      if (scanStatus === "running") return;

      setDomain(targetDomain);
      setScanStatus("running");
      setProgress(0);
      setLogs([]);
      setFindings([]);
      setSelectedFinding(null);
      setActiveFilter("all");
      setSearchQuery("");
      setCurrentStageIndex(0);
      setStageStates(SCAN_STAGES.map(() => "pending"));
      setSubsFound(0);

      const start = Date.now();
      setStartTime(start);

      // Elapsed timer
      timerRef.current = setInterval(() => {
        setElapsed(formatTime(Date.now() - start));
      }, 1000);

      // Simulate log streaming
      const totalLogs = DEMO_LOGS.length;
      const logInterval = 150; // ms between log entries
      let logIndex = 0;
      let subCount = 0;

      // Map log indices to stages
      const stageBreakpoints = [
        0,   // recon starts
        13,  // tls starts
        19,  // http starts
        25,  // cloud starts
        30,  // vuln starts
        42,  // analysis starts
      ];

      scanRef.current = setInterval(() => {
        if (logIndex >= totalLogs) {
          clearInterval(scanRef.current);
          clearInterval(timerRef.current);

          // Mark all stages complete
          setStageStates(SCAN_STAGES.map(() => "complete"));
          setProgress(100);

          // Brief delay then show results
          setTimeout(() => {
            setScanStatus("done");
            setFindings(DEMO_FINDINGS);
          }, 800);
          return;
        }

        const logEntry = DEMO_LOGS[logIndex];

        // Count subdomains
        if (logEntry.message.includes("Found subdomain")) {
          subCount++;
          setSubsFound(subCount);
        }

        // Add log with timestamp
        setLogs((prev) => [
          ...prev,
          {
            id: `log-${logIndex}`,
            timestamp: getNow(),
            type: logEntry.type,
            message: logEntry.message,
          },
        ]);

        // Update progress
        setProgress(Math.round(((logIndex + 1) / totalLogs) * 98));

        // Update stage states
        const stageIdx = stageBreakpoints.reduce((acc, bp, idx) => {
          return logIndex >= bp ? idx : acc;
        }, 0);

        setCurrentStageIndex(stageIdx);
        setStageStates((prev) => {
          const newStates = [...prev];
          for (let i = 0; i < newStates.length; i++) {
            if (i < stageIdx) newStates[i] = "complete";
            else if (i === stageIdx) newStates[i] = "running";
            else newStates[i] = "pending";
          }
          return newStates;
        });

        logIndex++;
      }, logInterval);
    },
    [scanStatus]
  );

  const resetScan = useCallback(() => {
    clearInterval(timerRef.current);
    clearInterval(scanRef.current);
    setScanStatus("idle");
    setDomain("");
    setProgress(0);
    setLogs([]);
    setFindings([]);
    setSelectedFinding(null);
    setActiveFilter("all");
    setSearchQuery("");
    setCurrentStageIndex(0);
    setStageStates(SCAN_STAGES.map(() => "pending"));
    setStartTime(null);
    setElapsed("0:00:00");
    setSubsFound(0);
  }, []);

  return {
    // State
    domain,
    scanStatus,
    progress,
    logs,
    findings,
    selectedFinding,
    activeFilter,
    searchQuery,
    currentStageIndex,
    stageStates,
    startTime,
    elapsed,
    subsFound,

    // Actions
    startScan,
    resetScan,
    setSelectedFinding,
    setActiveFilter,
    setSearchQuery,
    setDomain,
  };
}

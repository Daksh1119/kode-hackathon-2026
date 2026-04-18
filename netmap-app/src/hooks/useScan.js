import { useState, useCallback, useRef } from "react";
import { DEMO_FINDINGS, DEMO_LOGS, SCAN_STAGES } from "../data/mockFindings";

export function useScan() {
  const [domain, setDomain] = useState("");
  const [scanStatus, setScanStatus] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeFilter, setActiveFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [stageStates, setStageStates] = useState(SCAN_STAGES.map(() => "pending"));
  const [elapsed, setElapsed] = useState("0:00:00");
  const [subsFound, setSubsFound] = useState(0);
  const [hostsFound, setHostsFound] = useState(0);
  const [openPortsFound, setOpenPortsFound] = useState(0);

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

  // Stage breakpoints: which log index transitions to which stage
  const STAGE_BREAKPOINTS = [0, 8, 10, 14, 24, 26, 30];

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
      setStageStates(SCAN_STAGES.map(() => "pending"));
      setSubsFound(0);
      setHostsFound(0);
      setOpenPortsFound(0);

      const start = Date.now();

      // Elapsed timer
      timerRef.current = setInterval(() => {
        setElapsed(formatTime(Date.now() - start));
      }, 1000);

      const eventSource = new EventSource(`http://localhost:3001/api/scan?domain=${encodeURIComponent(targetDomain)}`);
      scanRef.current = eventSource;

      let subCount = 0;
      let logIndex = 0;

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === "done") {
            clearInterval(timerRef.current);
            scanRef.current.close();
            
            setStageStates(SCAN_STAGES.map(() => "complete"));
            setProgress(100);

            setTimeout(() => {
              setScanStatus("done");
              setFindings(data.findings || []);
            }, 800);
            return;
          }

          if (data.type === "process_exit") {
            return;
          }

          // Count subdomains (mock pattern kept for backwards compat)
          if (data.message.includes("Found subdomain")) {
            subCount++;
            setSubsFound(subCount);
          }

          // Real pipeline: hosts — "Fetching content for N live host(s)"
          const hostMatch = data.message.match(/Fetching content for (\d+) live host/);
          if (hostMatch) {
            setHostsFound(parseInt(hostMatch[1], 10));
          }

          // Real pipeline: also catch "N live subdomain(s)" from DNS stage
          const subMatch = data.message.match(/(\d+) live subdomain/);
          if (subMatch) {
            setHostsFound((prev) => Math.max(prev, parseInt(subMatch[1], 10)));
          }

          // Real pipeline: open ports — "[Nmap] Parsed N open port(s)"
          const portMatch = data.message.match(/\[Nmap\] Parsed (\d+) open port/);
          if (portMatch) {
            setOpenPortsFound(parseInt(portMatch[1], 10));
          }

          setLogs((prev) => [
            ...prev,
            {
              id: `log-${Date.now()}-${Math.random()}`,
              timestamp: getNow(),
              type: data.type || "info",
              message: data.message,
            },
          ]);

          // Simple progress heuristics based on stage markers
          if (data.message.includes("━━━  Stage")) {
            const stageMatch = data.message.match(/Stage (\d+)/);
            if (stageMatch) {
              const currentStage = parseInt(stageMatch[1], 10) - 1;
              const clampedStage = Math.min(currentStage, SCAN_STAGES.length - 1);
              
              setStageStates((prev) => {
                const newStates = [...prev];
                for (let i = 0; i < newStates.length; i++) {
                  if (i < clampedStage) newStates[i] = "complete";
                  else if (i === clampedStage) newStates[i] = "running";
                  else newStates[i] = "pending";
                }
                return newStates;
              });

              setProgress(Math.round(((clampedStage + 1) / 9) * 95));
            }
          }

          logIndex++;
        } catch (err) {
          console.error("Error parsing SSE data", err);
        }
      };

      eventSource.onerror = (err) => {
        console.error("SSE Error:", err);
        clearInterval(timerRef.current);
        scanRef.current.close();
        setScanStatus("done"); 
      };

    },
    [scanStatus]
  );

  const resetScan = useCallback(() => {
    clearInterval(timerRef.current);
    if (scanRef.current && scanRef.current.close) {
      scanRef.current.close(); // Close EventSource
    } else {
      clearInterval(scanRef.current); // Fallback if still interval
    }
    setScanStatus("idle");
    setDomain("");
    setProgress(0);
    setLogs([]);
    setFindings([]);
    setSelectedFinding(null);
    setActiveFilter("all");
    setSearchQuery("");
    setStageStates(SCAN_STAGES.map(() => "pending"));
    setElapsed("0:00:00");
    setSubsFound(0);
    setHostsFound(0);
    setOpenPortsFound(0);
  }, []);

  return {
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
    setDomain,
  };
}

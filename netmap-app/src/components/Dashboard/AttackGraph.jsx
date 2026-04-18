import React, { useRef, useCallback, useMemo, useEffect, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import {
  getUniqueHosts,
  getHostSeverity,
  getSeverityColor,
} from "../../utils/severityHelpers";

export default function AttackGraph({ findings, domain, onNodeClick }) {
  const graphRef = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 420 });

  useEffect(() => {
    const measure = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setDimensions({ width: Math.max(rect.width - 2, 400), height: 420 });
      }
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, []);

  const graphData = useMemo(() => {
    const nodes = [];
    const links = [];
    const hosts = getUniqueHosts(findings);

    // 1. Root Domain Node
    nodes.push({
      id: domain,
      label: domain,
      type: "domain",
      severity: "accent", // special color
      val: 20,
    });

    // 2. Subdomain Nodes
    hosts.forEach((host) => {
      // It's entirely possible a finding is directly on the root domain, treating it as a "host"
      if (host !== domain) {
        nodes.push({
          id: host,
          label: host.replace(`.${domain}`, ""),
          type: "subdomain",
          severity: getHostSeverity(findings, host),
          val: 12,
        });
        links.push({ source: domain, target: host });
      }
    });

    // 3. Ports & Findings
    const portSet = new Set();

    findings.forEach((f) => {
      // Ensure target host exists in nodes (fallback to domain if unexpected)
      const targetHostId = nodes.some((n) => n.id === f.host) ? f.host : domain;

      let parentId = targetHostId;

      // If finding has a port, insert a Port node between Host and Finding
      if (f.port) {
        const portId = `${f.host}:${f.port}`;
        if (!portSet.has(portId)) {
          portSet.add(portId);
          nodes.push({
            id: portId,
            label: `:${f.port}`,
            type: "port",
            severity: "low", // neutral
            val: 6,
          });
          links.push({ source: targetHostId, target: portId });
        }
        parentId = portId;
      }

      // Add the Finding (Asset / Risk) Node
      // Size depends on severity
      const sizeList = { high: 14, medium: 10, low: 8, info: 6 };
      nodes.push({
        id: f.id,
        findingObj: f, // Store finding details for click/hover
        label: f.source === "cloud" ? "Cloud Bucket" : f.title,
        type: "finding",
        severity: f.severity,
        val: sizeList[f.severity] || 8,
      });

      links.push({ source: parentId, target: f.id });
    });

    return { nodes, links };
  }, [findings, domain]);

  const paintNode = useCallback((node, ctx, globalScale) => {
    const size = node.val;

    // Core color logic to ensure original severity mapping over default cyan
    let color = "#00E5FF"; // default fallback
    const sevObj = {
      critical: "#FF3B5C",
      high: "#FF7043",
      medium: "#FFB300",
      low: "#00E5FF",
      info: "#3B82F6",
    };

    if (node.severity) {
      color = sevObj[node.severity.toLowerCase()] || "#00E5FF";
    }

    if (node.type === "domain") color = "#3A9E6E"; // original sage green brand color for root domain
    if (node.type === "port") color = "rgba(255,255,255,0.4)";

    ctx.shadowColor = color;
    ctx.shadowBlur = node.type === "finding" && node.severity === "high" ? 15 : (node.type === "domain" ? 14 : 4);

    if (node.type === "domain") {
      // Hexagon for root
      const a = (2 * Math.PI) / 6;
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        ctx.lineTo(
          node.x + size * Math.cos(a * i - Math.PI / 6),
          node.y + size * Math.sin(a * i - Math.PI / 6)
        );
      }
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
    } else if (node.type === "subdomain") {
      // Circle for subdomains
      ctx.beginPath();
      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
    } else if (node.type === "port") {
      // Small square for ports
      ctx.fillStyle = color;
      ctx.fillRect(node.x - size / 2, node.y - size / 2, size, size);
    } else if (node.type === "finding") {
      // Diamond for findings
      ctx.beginPath();
      ctx.moveTo(node.x, node.y - size);
      ctx.lineTo(node.x + size, node.y);
      ctx.lineTo(node.x, node.y + size);
      ctx.lineTo(node.x - size, node.y);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
    }

    ctx.shadowBlur = 0;

    // Label Rendering (Adaptive based on zoom level)
    // Only draw labels if we're zoomed in enough, or if it's a domain/subdomain
    const shouldDrawLabel = globalScale > 1.2 || node.type === "domain" || node.type === "subdomain";
    if (shouldDrawLabel) {
      const fontSize = node.type === "domain" ? 12 : 9;
      ctx.font = `${node.type === "domain" ? "bold " : ""}${fontSize}px 'JetBrains Mono', monospace`;
      ctx.fillStyle = node.type === "finding" ? "rgba(232, 237, 245, 0.6)" : "rgba(232, 237, 245, 0.85)";
      ctx.textAlign = "center";
      ctx.textBaseline = "top";

      // Shorten finding labels for display
      let displayLabel = node.label;
      if (node.type === "finding" && displayLabel.length > 20) {
        displayLabel = displayLabel.substring(0, 18) + "...";
      }

      ctx.fillText(displayLabel, node.x, node.y + size + 4);
    }
  }, []);

  const handleNodeClick = useCallback(
    (node) => {
      if (node.findingObj && onNodeClick) {
        onNodeClick(node.findingObj);
      }
    },
    [onNodeClick]
  );

  const handleNodeDragEnd = useCallback((node) => {
    // Pin nodes in place after user moves them manually
    node.fx = node.x;
    node.fy = node.y;
  }, []);

  // Update physics engine for wider spread (solving clusters)
  useEffect(() => {
    if (graphRef.current) {
      if (graphRef.current.d3Force) {
        // Increase repulsion enormously to prevent clustering
        graphRef.current.d3Force("charge").strength(-500);
        // Increase link distance to spread them out
        graphRef.current.d3Force("link").distance(100);
        // Restart the physics so they immediately spread on load
        graphRef.current.d3ReheatSimulation();
      }
    }
  }, [graphData]);

  const nodeTooltip = useCallback(
    (node) => {
      if (node.type === "domain")
        return `<div style="background:#181F2E;color:#E8EDF5;padding:8px 12px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:11px;border:1px solid rgba(255,255,255,0.07)"><strong>${node.id}</strong><br/><span style="color:#00E5FF">Root Domain</span></div>`;
      if (node.type === "subdomain") {
        const hostFindings = findings.filter((f) => f.host === node.id);
        const color = getSeverityColor(node.severity);
        return `<div style="background:#181F2E;color:#E8EDF5;padding:8px 12px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:11px;border:1px solid rgba(255,255,255,0.07)"><strong>${node.id}</strong><br/><span style="color:${color}">● ${node.severity.toUpperCase()}</span> · ${hostFindings.length} issue${hostFindings.length !== 1 ? "s" : ""}</div>`;
      }
      if (node.type === "port") {
        return `<div style="background:#181F2E;color:#E8EDF5;padding:8px 12px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:11px;border:1px solid rgba(255,255,255,0.07)"><strong>Port ${node.label.replace(':', '')}</strong><br/><span style="color:rgba(255,255,255,0.6)">Open Service</span></div>`;
      }
      if (node.type === "finding") {
        const color = getSeverityColor(node.severity);
        const tierStr = node.findingObj.priority_tier ? ` · <span style="color:${color}">${node.findingObj.priority_tier}</span>` : "";
        return `<div style="background:#181F2E;color:#E8EDF5;padding:8px 12px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:11px;border:1px solid rgba(255,255,255,0.07); white-space:nowrap; max-width: 300px; overflow: hidden; text-overflow: ellipsis"><strong>${node.findingObj.title}</strong><br/><span style="color:${color}">● ${node.severity.toUpperCase()}</span>${tierStr}</div>`;
      }
      return "";
    },
    [findings]
  );

  return (
    <div
      ref={containerRef}
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 10,
        overflow: "hidden",
        height: 420,
        position: "relative",
        backgroundImage: "radial-gradient(rgba(255,255,255,0.015) 1px, transparent 1px)",
        backgroundSize: "20px 20px",
      }}
    >
      {/* Label overlay */}
      <div
        style={{
          position: "absolute",
          top: 14,
          left: 16,
          zIndex: 2,
          pointerEvents: "none",
          display: "flex",
          justifyContent: "space-between",
          right: 16,
          alignItems: "center"
        }}
      >
        <span
          className="font-mono"
          style={{
            fontSize: 11,
            fontWeight: 600,
            color: "#FFFFFF",
            textTransform: "uppercase",
            letterSpacing: "0.15em",
          }}
        >
          Attack Surface Map
        </span>
      </div>

      <div style={{ width: "100%", height: "100%" }}>
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          width={dimensions.width}
          height={dimensions.height}
          backgroundColor="transparent"
          linkColor={() => "rgba(255,255,255,0.07)"}
          linkWidth={1}
          nodeCanvasObject={paintNode}
          nodePointerAreaPaint={(node, color, ctx) => {
            const size = node.val + 2; // Allow slightly larger hit area
            ctx.beginPath();
            ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
            ctx.fillStyle = color;
            ctx.fill();
          }}
          onNodeClick={handleNodeClick}
          onNodeDragEnd={handleNodeDragEnd}
          nodeLabel={nodeTooltip}
          warmupTicks={250}
          cooldownTicks={100}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
          enableZoomInteraction={true}
          enablePanInteraction={true}
        />
      </div>
    </div>
  );
}

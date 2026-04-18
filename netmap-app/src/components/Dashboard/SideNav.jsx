import React from "react";
import {
  Network,
  Radio,
  Cloud,
  FolderSearch,
  ScrollText,
  FileWarning,
} from "lucide-react";

const NAV_ITEMS = [
  {
    id: "attack",
    label: "Attack Surface Maps",
    icon: Network,
    shortLabel: "Attack Map",
  },
  {
    id: "ports",
    label: "Open Ports",
    icon: Radio,
    shortLabel: "Open Ports",
  },
  {
    id: "cloud",
    label: "Cloud Issues",
    icon: Cloud,
    shortLabel: "Cloud",
  },
  {
    id: "hidden",
    label: "Hidden Files",
    icon: FolderSearch,
    shortLabel: "Hidden Files",
  },
  {
    id: "logs",
    label: "Logs",
    icon: ScrollText,
    shortLabel: "Logs",
  },
  {
    id: "files",
    label: "Sensitive Files",
    icon: FileWarning,
    shortLabel: "Files",
  },
];

import {
  Menu,
  ChevronLeft,
  ChevronRight
} from "lucide-react";

export default function SideNav({ activeTab, onTabChange, findings, logs, isCollapsed, onToggle }) {
  const getCounts = (tabId) => {
    switch (tabId) {
      case "ports":
        return findings.filter((f) => f.port != null || f.source === "nmap")
          .length;
      case "cloud":
        return findings.filter((f) => f.source === "cloud").length;
      case "hidden":
        return findings.filter(
          (f) =>
            f.source === "engine" ||
            f.title?.toLowerCase().includes("hidden") ||
            f.title?.toLowerCase().includes("director") ||
            f.title?.toLowerCase().includes("admin") ||
            f.title?.toLowerCase().includes("panel")
        ).length;
      case "files":
        return findings.filter((f) => f.source === "file_scanner").length;
      case "logs":
        return logs?.length || 0;
      default:
        return null;
    }
  };

  return (
    <aside
      style={{
        position: "fixed",
        top: 56, // Header height
        left: 0,
        bottom: 0,
        width: isCollapsed ? 68 : 220,
        zIndex: 40,
        display: "flex",
        flexDirection: "column",
        background: "var(--sidenav-bg)",
        borderRight: "1px solid var(--border)",
        overflow: "hidden",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        transition: "width var(--duration-base) var(--ease-smooth)",
      }}
    >
      {/* Right border click area to toggle */}
      <div 
        onClick={onToggle}
        style={{
          position: "absolute",
          top: 0,
          right: 0,
          bottom: 0,
          width: 8,
          cursor: "ew-resize",
          zIndex: 50,
          transition: "background 0.2s",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.06)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      />

      {/* Top Header */}
      <div
        style={{
          padding: isCollapsed ? "18px 0 10px" : "18px 16px 10px",
          borderBottom: "1px solid var(--border)",
          flexShrink: 0,
          display: "flex",
          justifyContent: isCollapsed ? "center" : "space-between",
          alignItems: "center"
        }}
      >
        {!isCollapsed && (
          <h2
            className="font-display"
            style={{
              fontSize: 15,
              fontWeight: 600,
              color: "var(--text-primary)",
              letterSpacing: "0.05em",
              whiteSpace: "nowrap",
              margin: 0
            }}
          >
            Navigation
          </h2>
        )}
        
        <button
          onClick={onToggle}
          style={{
            background: "transparent",
            border: "none",
            color: "var(--text-2)",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 4,
            transition: "color var(--duration-base)"
          }}
          onMouseEnter={e => e.currentTarget.style.color = "var(--text)"}
          onMouseLeave={e => e.currentTarget.style.color = "var(--text-2)"}
        >
          {isCollapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </button>
      </div>

      {/* Nav Items */}
      <nav
        style={{
          flex: 1,
          padding: "8px 8px",
          display: "flex",
          flexDirection: "column",
          gap: 2,
          overflowY: "auto",
        }}
      >
        {NAV_ITEMS.map((item) => {
          const isActive = activeTab === item.id;
          const Icon = item.icon;
          const count = getCounts(item.id);

          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              title={item.label}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: isCollapsed ? "center" : "flex-start",
                gap: 10,
                padding: isCollapsed ? "12px 0" : "9px 12px",
                borderRadius: 10,
                border: "none",
                cursor: "pointer",
                background: isActive ? "var(--sidenav-active-bg)" : "transparent",
                color: isActive ? "var(--green-accent)" : "var(--text-2)",
                fontFamily: "var(--font-body)",
                fontSize: 13,
                fontWeight: isActive ? 600 : 400,
                textAlign: "left",
                width: "100%",
                transition: "all 150ms var(--ease-smooth)",
                position: "relative",
                boxShadow: isActive
                  ? "0 1px 3px rgba(0,0,0,0.25)"
                  : "none",
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = "var(--sidenav-hover-bg)";
                  e.currentTarget.style.color = "var(--text)";
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = "transparent";
                  e.currentTarget.style.color = "var(--text-2)";
                }
              }}
            >
              {/* Active indicator */}
              {isActive && (
                <span
                  style={{
                    position: "absolute",
                    left: 0,
                    top: "50%",
                    transform: "translateY(-50%)",
                    width: 3,
                    height: 20,
                    borderRadius: "0 3px 3px 0",
                    background: "var(--green-accent)",
                  }}
                />
              )}

              <Icon
                size={isCollapsed ? 18 : 15}
                style={{
                  flexShrink: 0,
                  color: isActive ? "var(--green-accent)" : "inherit",
                  strokeWidth: isActive ? 2.2 : 1.8,
                  transition: "all var(--duration-base)",
                }}
              />

              {!isCollapsed && (
                <span style={{ flex: 1, lineHeight: 1.3, whiteSpace: "nowrap" }}>{item.label}</span>
              )}

              {/* Badge */}
              {count != null && count > 0 && !isCollapsed && (
                <span
                  className="font-mono"
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    padding: "1px 6px",
                    borderRadius: 999,
                    background: isActive
                      ? "var(--green-accent-dim)"
                      : "var(--elevated)",
                    color: isActive ? "var(--green-accent)" : "var(--text-3)",
                    flexShrink: 0,
                    lineHeight: 1.6,
                  }}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom divider + version */}
      <div
        style={{
          padding: isCollapsed ? "12px 0" : "12px 16px",
          borderTop: "1px solid var(--border)",
          flexShrink: 0,
          display: "flex",
          justifyContent: "center",
          alignItems: "center"
        }}
      >
        {!isCollapsed && (
          <span
            className="font-mono"
            style={{
              fontSize: 9,
              color: "var(--text-3)",
              letterSpacing: "0.1em",
              whiteSpace: "nowrap"
            }}
          >
            NETMAP v1.0
          </span>
        )}
      </div>
    </aside>
  );
}

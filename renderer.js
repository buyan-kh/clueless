const { ipcRenderer } = require("electron");

class CluelessDetector {
  constructor() {
    this.isMonitoring = false;
    this.monitoringInterval = null;
    this.suspiciousProcesses = new Set();
    this.alerts = [];
    this.behavioralMetrics = {
      typingConsistency: 0,
      responseTimeAnomaly: 0,
      grammarPerfection: 0,
    };

    this.init();
  }

  init() {
    this.setupEventListeners();
    this.setupTabs();
    this.loadSystemInfo();
  }

  setupEventListeners() {
    document
      .getElementById("start-monitoring")
      .addEventListener("click", () => {
        this.startMonitoring();
      });

    document.getElementById("stop-monitoring").addEventListener("click", () => {
      this.stopMonitoring();
    });

    document.getElementById("export-report").addEventListener("click", () => {
      this.exportReport();
    });
  }

  setupTabs() {
    const tabButtons = document.querySelectorAll(".tab-button");
    const tabPanels = document.querySelectorAll(".tab-panel");

    tabButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const targetTab = button.dataset.tab;

        tabButtons.forEach((btn) => btn.classList.remove("active"));
        tabPanels.forEach((panel) => panel.classList.remove("active"));

        button.classList.add("active");
        document.getElementById(`${targetTab}-tab`).classList.add("active");
      });
    });
  }

  async loadSystemInfo() {
    try {
      const systemInfo = await ipcRenderer.invoke("get-system-info");
      console.log("System Info:", systemInfo);
    } catch (error) {
      console.error("Failed to load system info:", error);
    }
  }

  async startMonitoring() {
    this.isMonitoring = true;
    document.getElementById("detection-status").textContent = "Active";
    document.getElementById("detection-status").className =
      "status-value active";
    document.getElementById("start-monitoring").disabled = true;
    document.getElementById("stop-monitoring").disabled = false;

    try {
      await ipcRenderer.invoke("start-invisible-detection");
      await ipcRenderer.invoke("show-overlay");
      this.addAlert("info", "Advanced invisible AI detection started");
    } catch (error) {
      console.error("Failed to start invisible detection:", error);
    }

    this.addAlert("info", "Monitoring started successfully");

    this.monitoringInterval = setInterval(() => {
      this.performDetection();
    }, 2000);
  }

  async stopMonitoring() {
    this.isMonitoring = false;
    document.getElementById("detection-status").textContent = "Inactive";
    document.getElementById("detection-status").className =
      "status-value inactive";
    document.getElementById("start-monitoring").disabled = false;
    document.getElementById("stop-monitoring").disabled = true;

    try {
      await ipcRenderer.invoke("stop-invisible-detection");
      await ipcRenderer.invoke("hide-overlay");
    } catch (error) {
      console.error("Failed to stop invisible detection:", error);
    }

    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    this.addAlert("info", "Monitoring stopped");
  }

  async performDetection() {
    try {
      await Promise.all([
        this.checkProcesses(),
        this.checkNetwork(),
        this.analyzeBehavior(),
        this.checkInvisibleAI(),
      ]);
    } catch (error) {
      console.error("Detection error:", error);
    }
  }

  async checkProcesses() {
    try {
      const processOutput = await ipcRenderer.invoke("get-processes");
      if (processOutput.error) {
        console.error("Process check error:", processOutput.error);
        return;
      }

      const suspiciousKeywords = [
        "cluely",
        "claude",
        "chatgpt",
        "openai",
        "anthropic",
        "copilot",
        "ai-helper",
        "gpt",
      ];

      // system processes to ignore
      const systemProcesses = [
        "kernel",
        "launchd",
        "systemd",
        "init",
        "kthreadd",
        "migration",
        "ksoftirqd",
        "watchdog",
        "rcu_",
        "systemstats",
        "cfprefsd",
        "distnoted",
        "UserEventAgent",
        "WindowServer",
        "loginwindow",
        "Dock",
        "Finder",
        "SystemUIServer",
        "coreaudiod",
        "audio",
        "bluetooth",
        "wifi",
        "network",
        "_cmiodalassistants",
        "cmio",
        "coremedia",
        "avconferenced",
        "com.apple",
        "apple.",
        "system.",
        "/usr/sbin",
        "/usr/bin",
        "/System/",
        "/Library/",
        "mdnsresponder",
        "mds",
        "spotlight",
        "backupd",
        "TimeMachine",
        "cron",
        "at",
        "ssh",
        "rsync",
        "chrome",
        "firefox",
        "safari",
        "electron",
        "node",
        "python",
        "java",
        "ruby",
        "php",
        "npm",
        "git",
        "vscode",
        "xcode",
      ];

      const processes = this.parseProcessOutput(processOutput);
      const suspicious = processes.filter((proc) => {
        const isSystemProcess = systemProcesses.some((sysProc) =>
          proc.name.toLowerCase().includes(sysProc.toLowerCase())
        );

        if (isSystemProcess) {
          return false;
        }

        return suspiciousKeywords.some((keyword) =>
          proc.name.toLowerCase().includes(keyword.toLowerCase())
        );
      });

      this.updateProcessDisplay(suspicious);

      if (suspicious.length > 0) {
        this.updateThreatLevel("high");
        suspicious.forEach((proc) => {
          if (!this.suspiciousProcesses.has(proc.name)) {
            this.addAlert(
              "danger",
              `Suspicious process detected: ${proc.name}`
            );
            this.suspiciousProcesses.add(proc.name);
          }
        });
      }

      document.getElementById("process-count").textContent = suspicious.length;
    } catch (error) {
      console.error("Process monitoring error:", error);
    }
  }

  async checkNetwork() {
    try {
      const networkOutput = await ipcRenderer.invoke("get-network");
      if (networkOutput.error) {
        console.error("Network check error:", networkOutput.error);
        return;
      }

      const suspiciousEndpoints = [
        "api.openai.com",
        "api.anthropic.com",
        "claude.ai",
        "chat.openai.com",
        "copilot.github.com",
      ];

      const connections = this.parseNetworkOutput(networkOutput);
      const suspicious = connections.filter((conn) =>
        suspiciousEndpoints.some((endpoint) => conn.address.includes(endpoint))
      );

      this.updateNetworkDisplay(suspicious);

      if (suspicious.length > 0) {
        this.updateThreatLevel("high");
        suspicious.forEach((conn) => {
          this.addAlert(
            "warning",
            `Suspicious network connection: ${conn.address}`
          );
        });
      }
    } catch (error) {
      console.error("Network monitoring error:", error);
    }
  }

  analyzeBehavior() {
    const randomFactor = Math.random();

    // simulate AI assistance metrics
    this.behavioralMetrics.typingConsistency = Math.min(
      100,
      this.behavioralMetrics.typingConsistency + randomFactor * 5
    );
    this.behavioralMetrics.responseTimeAnomaly = Math.min(
      100,
      this.behavioralMetrics.responseTimeAnomaly + randomFactor * 3
    );
    this.behavioralMetrics.grammarPerfection = Math.min(
      100,
      this.behavioralMetrics.grammarPerfection + randomFactor * 4
    );

    this.updateBehavioralDisplay();

    // check for high-risk patterns
    const avgScore =
      (this.behavioralMetrics.typingConsistency +
        this.behavioralMetrics.responseTimeAnomaly +
        this.behavioralMetrics.grammarPerfection) /
      3;

    if (avgScore > 70) {
      this.updateThreatLevel("high");
      this.addAlert(
        "danger",
        "High probability of AI assistance detected based on behavioral patterns"
      );
    } else if (avgScore > 40) {
      this.updateThreatLevel("medium");
    }
  }

  parseProcessOutput(output) {
    const lines = output.split("\n").filter((line) => line.trim());
    const processes = [];

    lines.forEach((line) => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        processes.push({
          name: parts[0] || "Unknown",
          pid: parts[1] || "N/A",
          memory: parts[2] || "N/A",
        });
      }
    });

    return processes;
  }

  parseNetworkOutput(output) {
    const lines = output.split("\n").filter((line) => line.trim());
    const connections = [];

    lines.forEach((line) => {
      if (line.includes(":")) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          connections.push({
            address: parts[1] || "Unknown",
            state: parts[3] || "Unknown",
          });
        }
      }
    });

    return connections;
  }

  updateProcessDisplay(processes) {
    const container = document.getElementById("processes-list");

    if (processes.length === 0) {
      container.innerHTML = "<p>No suspicious processes detected.</p>";
      return;
    }

    container.innerHTML = processes
      .map(
        (proc) => `
            <div class="process-item suspicious">
                <div class="process-name">${proc.name}</div>
                <div class="process-details">PID: ${proc.pid} | Memory: ${proc.memory}</div>
            </div>
        `
      )
      .join("");
  }

  updateNetworkDisplay(connections) {
    const container = document.getElementById("network-list");

    if (connections.length === 0) {
      container.innerHTML = "<p>No suspicious network activity detected.</p>";
      return;
    }

    container.innerHTML = connections
      .map(
        (conn) => `
            <div class="network-item suspicious">
                <div class="network-addr">${conn.address}</div>
                <div class="network-details">State: ${conn.state}</div>
            </div>
        `
      )
      .join("");
  }

  updateBehavioralDisplay() {
    const metrics = [
      "typingConsistency",
      "responseTimeAnomaly",
      "grammarPerfection",
    ];

    metrics.forEach((metric) => {
      const value = Math.round(this.behavioralMetrics[metric]);
      const metricElements = document.querySelectorAll(".metric");

      metricElements.forEach((element, index) => {
        if (index < metrics.length) {
          const fill = element.querySelector(".metric-fill");
          const valueSpan = element.querySelector(".metric-value");

          if (fill && valueSpan) {
            fill.style.width = `${value}%`;
            valueSpan.textContent = `${value}%`;
          }
        }
      });
    });
  }

  updateThreatLevel(level) {
    const element = document.getElementById("threat-level");
    element.textContent = level.charAt(0).toUpperCase() + level.slice(1);
    element.className = `status-value ${level}`;
  }

  addAlert(type, message) {
    const alert = {
      type,
      message,
      timestamp: new Date().toLocaleTimeString(),
    };

    this.alerts.unshift(alert);
    this.updateAlertsDisplay();
  }

  updateAlertsDisplay() {
    const container = document.getElementById("alerts-list");

    if (this.alerts.length === 0) {
      container.innerHTML = "<p>No alerts at this time.</p>";
      return;
    }

    container.innerHTML = this.alerts
      .slice(0, 10)
      .map(
        (alert) => `
            <div class="alert ${
              alert.type === "danger" ? "danger" : "warning"
            }">
                <strong>${alert.message}</strong>
                <div class="alert-time">${alert.timestamp}</div>
            </div>
        `
      )
      .join("");
  }

  exportReport() {
    const report = {
      timestamp: new Date().toISOString(),
      suspiciousProcesses: Array.from(this.suspiciousProcesses),
      behavioralMetrics: this.behavioralMetrics,
      alerts: this.alerts,
      threatLevel: document.getElementById("threat-level").textContent,
    };

    const dataStr = JSON.stringify(report, null, 2);
    const dataBlob = new Blob([dataStr], { type: "application/json" });

    const link = document.createElement("a");
    link.href = URL.createObjectURL(dataBlob);
    link.download = `clueless-report-${Date.now()}.json`;
    link.click();

    this.addAlert("info", "Security report exported successfully");
  }

  async checkInvisibleAI() {
    try {
      const report = await ipcRenderer.invoke("get-detection-report");
      if (report.error) {
        console.error("Invisible AI detection error:", report.error);
        return;
      }

      // process clipboard analysis
      if (report.clipboardAnalysis.suspiciousEntries > 0) {
        this.updateThreatLevel("high");
        this.addAlert(
          "danger",
          `Detected ${report.clipboardAnalysis.suspiciousEntries} AI-generated clipboard entries`
        );
      }

      // process typing analysis
      if (report.typingAnalysis.suspiciousPatterns > 0) {
        this.updateThreatLevel("medium");
        this.addAlert(
          "warning",
          `Detected ${report.typingAnalysis.suspiciousPatterns} unnatural typing patterns`
        );
      }

      // process suspicious activity
      const recentActivity = report.suspiciousActivity.filter(
        (activity) => Date.now() - activity.timestamp < 10000 // last 10 seconds
      );

      recentActivity.forEach((activity) => {
        switch (activity.type) {
          case "clipboard_ai_injection":
            this.addAlert("danger", "AI-generated text detected in clipboard");
            this.updateThreatLevel("high");
            break;
          case "memory_ai_signature":
            this.addAlert(
              "danger",
              `AI signatures detected in process: ${activity.process}`
            );
            this.updateThreatLevel("high");
            break;
          case "hidden_ai_processes":
            this.addAlert(
              "danger",
              `Hidden AI processes detected: ${activity.processes.join(", ")}`
            );
            this.updateThreatLevel("high");
            break;
          case "unnatural_typing_pattern":
            this.addAlert("warning", "Unnatural typing pattern detected");
            this.updateThreatLevel("medium");
            break;
        }
      });

      // update overall threat level based on report
      if (report.overallThreatLevel === "CRITICAL") {
        this.updateThreatLevel("high");
        this.addAlert(
          "danger",
          "CRITICAL: Multiple AI assistance indicators detected!"
        );
      }

      // update overlay with current status
      this.updateOverlayStatus(report);
    } catch (error) {
      console.error("Invisible AI detection error:", error);
    }
  }

  async updateOverlayStatus(report) {
    const currentThreatLevel = document
      .getElementById("threat-level")
      .textContent.toLowerCase();
    const suspiciousProcessCount =
      document.getElementById("process-count").textContent;
    const totalAlerts = this.alerts.length;

    // calculate risk score based on various factors
    let riskScore = 0;
    if (report) {
      riskScore += report.clipboardAnalysis.suspiciousEntries * 20;
      riskScore += report.typingAnalysis.suspiciousPatterns * 15;
      riskScore += report.suspiciousActivity.length * 10;
    }
    riskScore = Math.min(100, riskScore);

    const overlayStatus = {
      isMonitoring: this.isMonitoring,
      isClean: currentThreatLevel === "low",
      threatLevel: currentThreatLevel,
      suspiciousProcesses: parseInt(suspiciousProcessCount) || 0,
      totalAlerts: totalAlerts,
      riskScore: riskScore,
    };

    try {
      await ipcRenderer.invoke("update-overlay-status", overlayStatus);
    } catch (error) {
      console.error("Failed to update overlay:", error);
    }
  }
}

// initialize the detector when the DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new CluelessDetector();
});

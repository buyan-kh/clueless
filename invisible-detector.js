const { spawn, exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

class InvisibleAIDetector {
  constructor() {
    this.keystrokeBuffer = [];
    this.clipboardHistory = [];
    this.typingPatterns = new Map();
    this.suspiciousActivity = [];
    this.isMonitoring = false;
  }

  startDeepMonitoring() {
    this.isMonitoring = true;
    this.startClipboardMonitoring();
    this.startKeystrokeAnalysis();
    this.startMemoryScanning();
    this.startInvisibleProcessDetection();
  }

  stopDeepMonitoring() {
    this.isMonitoring = false;
  }

  startClipboardMonitoring() {
    try {
      const clipboard = require("clipboard-event");
      let lastClipboard = "";

      clipboard.startListening();

      clipboard.on("change", () => {
        if (!this.isMonitoring) return;

        try {
          const currentClipboard = clipboard.readText();

          if (currentClipboard !== lastClipboard) {
            this.analyzeClipboardContent(currentClipboard);
            this.clipboardHistory.push({
              content: currentClipboard,
              timestamp: Date.now(),
              suspicious: this.isAIGeneratedText(currentClipboard),
            });
            lastClipboard = currentClipboard;
          }
        } catch (error) {
          console.error("Clipboard monitoring error:", error);
        }
      });
    } catch (error) {
      console.error("Failed to start clipboard monitoring:", error);
    }
  }

  // detect AI-generated text patterns
  isAIGeneratedText(text) {
    if (!text || text.length < 100) return false;

    const aiIndicators = [
      /^[A-Z][^.!?]*[.!?](\s+[A-Z][^.!?]*[.!?])*$/,
      /\b(furthermore|moreover|additionally|consequently|therefore|nevertheless)\b/gi,
      /\b(I'd be happy to|I'd be glad to|feel free to|please don't hesitate|as an AI)\b/gi,
      /^[^,]*,\s+[^,]*,\s+and\s+[^.]*\.$/,
      /^\d+\.\s+.*\n\d+\.\s+.*\n\d+\.\s+/m,
    ];

    let suspiciousScore = 0;

    aiIndicators.forEach((pattern) => {
      if (pattern.test(text)) suspiciousScore++;
    });

    // check for unnatural perfection
    const sentences = text.split(/[.!?]+/).filter((s) => s.trim().length > 0);
    if (sentences.length > 3) {
      const avgLength =
        sentences.reduce((sum, s) => sum + s.length, 0) / sentences.length;
      const lengthVariance =
        sentences.reduce(
          (sum, s) => sum + Math.pow(s.length - avgLength, 2),
          0
        ) / sentences.length;

      if (lengthVariance < 50 && avgLength > 60) {
        suspiciousScore += 1;
      }
    }

    return suspiciousScore >= 3;
  }

  analyzeClipboardContent(content) {
    if (this.isAIGeneratedText(content)) {
      this.suspiciousActivity.push({
        type: "clipboard_ai_injection",
        content: content.substring(0, 100) + "...",
        timestamp: Date.now(),
        severity: "high",
      });
    }
  }

  startKeystrokeAnalysis() {
    // simulate keystroke analysis
    setInterval(() => {
      if (!this.isMonitoring) return;
      this.analyzeTypingPatterns();
    }, 1000);
  }

  analyzeTypingPatterns() {
    const currentTime = Date.now();

    // AI-assisted typing patterns
    const simulatedPattern = {
      avgKeystrokeInterval: 80 + Math.random() * 50,
      backspaceRatio: Math.random() * 0.15,
      pauseFrequency: Math.random() * 0.3,
      burstTyping: Math.random() > 0.9
    };

    this.typingPatterns.set(currentTime, simulatedPattern);

    if (
      simulatedPattern.avgKeystrokeInterval < 40 &&
      simulatedPattern.backspaceRatio < 0.01 &&
      simulatedPattern.pauseFrequency < 0.02
    ) {
      this.suspiciousActivity.push({
        type: "unnatural_typing_pattern",
        details: simulatedPattern,
        timestamp: currentTime,
        severity: "low"
      });
    }
  }

  startMemoryScanning() {
    setInterval(() => {
      if (!this.isMonitoring) return;
      this.scanForAISignatures();
    }, 5000);
  }

  async scanForAISignatures() {
    try {
      const aiSignatures = [
        "anthropic",
        "claude",
        "openai",
        "gpt-",
        "assistant",
        "completion",
        "prompt",
        "tokens",
        "model_name",
        "api_key",
        "ai_response",
        "generated_text",
      ];

      if (os.platform() !== "win32") {
        const psOutput = await this.execCommand("ps aux");
        const processes = psOutput.split("\n").slice(1);

        for (const processLine of processes) {
          const parts = processLine.trim().split(/\s+/);
          if (parts.length >= 2) {
            const pid = parts[1];
            const processName = parts[10] || "";

            if (
              processName.includes("kernel") ||
              processName.includes("clueless")
            ) {
              continue;
            }

            try {
              const memoryContent = await this.execCommand(
                `strings /proc/${pid}/mem 2>/dev/null | head -1000`
              );

              const foundSignatures = aiSignatures.filter((sig) =>
                memoryContent.toLowerCase().includes(sig.toLowerCase())
              );

              if (foundSignatures.length > 0) {
                this.suspiciousActivity.push({
                  type: "memory_ai_signature",
                  process: processName,
                  pid: pid,
                  signatures: foundSignatures,
                  timestamp: Date.now(),
                  severity: "high",
                });
              }
            } catch (error) {
            }
          }
        }
      }
    } catch (error) {
      console.error("Memory scanning error:", error);
    }
  }

  async startInvisibleProcessDetection() {
    setInterval(async () => {
      if (!this.isMonitoring) return;
      await this.detectHiddenProcesses();
    }, 3000);
  }

  async detectHiddenProcesses() {
    try {
      const platform = os.platform();
      let hiddenProcesses = [];

      if (platform === "darwin") {
        const allProcesses = await this.execCommand("ps aux");
        const visibleWindows = await this.execCommand(
          'osascript -e "tell application \\"System Events\\" to get name of every process whose visible is true"'
        );

        const processNames = allProcesses
          .split("\n")
          .map((line) => {
            const parts = line.trim().split(/\s+/);
            return parts[10] || "";
          })
          .filter((name) => name.length > 0);

        const visibleNames = visibleWindows
          .split(", ")
          .map((name) => name.trim());

        hiddenProcesses = processNames.filter(
          (proc) =>
            !visibleNames.includes(proc) && this.isLikelyAIAssistant(proc)
        );
      } else if (platform === "win32") {
        const tasklistOutput = await this.execCommand("tasklist /v /fo csv");
        const lines = tasklistOutput.split("\n").slice(1);

        for (const line of lines) {
          const fields = line
            .split(",")
            .map((field) => field.replace(/"/g, ""));
          if (fields.length >= 8) {
            const processName = fields[0];
            const windowTitle = fields[8];

            if (
              this.isLikelyAIAssistant(processName) &&
              (windowTitle === "N/A" || windowTitle.includes("Hidden"))
            ) {
              hiddenProcesses.push(processName);
            }
          }
        }
      }

      if (hiddenProcesses.length > 0) {
        this.suspiciousActivity.push({
          type: "hidden_ai_processes",
          processes: hiddenProcesses,
          timestamp: Date.now(),
          severity: "high",
        });
      }
    } catch (error) {
      console.error("Hidden process detection error:", error);
    }
  }

  isLikelyAIAssistant(processName) {
    const aiKeywords = [
      "cluely",
      "claude",
      "chatgpt",
      "openai",
      "anthropic",
      "copilot",
      "ai-helper",
      "gpt",
      "llm",
      "completion",
      "prompt",
      "neural",
      "model",
    ];

    // system processes to exclude
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

    const isSystemProcess = systemProcesses.some((sysProc) =>
      processName.toLowerCase().includes(sysProc.toLowerCase())
    );

    if (isSystemProcess) {
      return false;
    }

    return aiKeywords.some((keyword) =>
      processName.toLowerCase().includes(keyword.toLowerCase())
    );
  }

  async execCommand(command) {
    return new Promise((resolve, reject) => {
      exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve(stdout);
        }
      });
    });
  }

  getDetectionReport() {
    return {
      timestamp: new Date().toISOString(),
      suspiciousActivity: this.suspiciousActivity,
      clipboardAnalysis: {
        totalEntries: this.clipboardHistory.length,
        suspiciousEntries: this.clipboardHistory.filter(
          (entry) => entry.suspicious
        ).length,
        recentSuspicious: this.clipboardHistory
          .filter((entry) => entry.suspicious)
          .slice(-5)
          .map((entry) => ({
            content: entry.content.substring(0, 100) + "...",
            timestamp: new Date(entry.timestamp).toISOString(),
          })),
      },
      typingAnalysis: {
        totalPatterns: this.typingPatterns.size,
        suspiciousPatterns: Array.from(this.typingPatterns.values()).filter(
          (pattern) =>
            pattern.avgKeystrokeInterval < 60 && pattern.backspaceRatio < 0.02
        ).length,
      },
      overallThreatLevel: this.calculateThreatLevel(),
    };
  }

  calculateThreatLevel() {
    const highSeverityCount = this.suspiciousActivity.filter(
      (a) => a.severity === "high"
    ).length;
    const mediumSeverityCount = this.suspiciousActivity.filter(
      (a) => a.severity === "medium"
    ).length;

    if (highSeverityCount >= 3) return "CRITICAL";
    if (highSeverityCount >= 1 || mediumSeverityCount >= 3) return "HIGH";
    if (mediumSeverityCount >= 1) return "MEDIUM";
    return "LOW";
  }

  clearHistory() {
    this.suspiciousActivity = [];
    this.clipboardHistory = [];
    this.typingPatterns.clear();
  }
}

module.exports = InvisibleAIDetector;

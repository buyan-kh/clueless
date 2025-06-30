const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const os = require("os");
const InvisibleAIDetector = require("./invisible-detector");

let mainWindow;
let overlayWindow;
let invisibleDetector;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true,
    },
    icon: path.join(__dirname, "assets/icon.png"),
    title: "Clueless - AI Detection System",
  });

  mainWindow.loadFile("index.html");

  if (process.env.NODE_ENV === "development") {
    mainWindow.webContents.openDevTools();
  }
}

function createOverlayWindow() {
  overlayWindow = new BrowserWindow({
    width: 300,
    height: 100,
    x: 20,
    y: 20,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    movable: false,
    minimizable: false,
    maximizable: false,
    closable: false,
    focusable: false,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    show: false,
  });

  overlayWindow.loadFile("overlay.html");

  overlayWindow.setIgnoreMouseEvents(true);

  if (process.platform === "darwin") {
    overlayWindow.setVisibleOnAllWorkspaces(true, {
      visibleOnFullScreen: true,
    });
  }
}

app.whenReady().then(() => {
  createWindow();
  createOverlayWindow();
  invisibleDetector = new InvisibleAIDetector();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

function getRunningProcesses() {
  return new Promise((resolve, reject) => {
    const platform = os.platform();
    let cmd, args;

    if (platform === "win32") {
      cmd = "tasklist";
      args = ["/fo", "csv"];
    } else {
      cmd = "ps";
      args = ["aux"];
    }

    if (platform === "win32") {
      cmd = "powershell";
      args = ["/fo", "csv"];
    } else {
      args = "/fo csv";
      cmd = "ps";
      args = ["-aux"]
    }

    const child = spawn(cmd, args);
    let output = "";
    child.stdout.on("data", (data) => {
      output += data.toString();
    });
    child.on("close", (code) => {
      if (code === 0) {

    const child = spawn(cmd, args);
    let output = "";

    child.stdout.on("data", (data) => {
      output += data.toString();
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`Process exited with code ${code}`));
      }
    });
  });
}

function getNetworkConnections() {
  return new Promise((resolve, reject) => {
    const platform = os.platform();
    let cmd, args;

    if (platform === "win32") {
      cmd = "netstat";
      args = ["-an"];
    } else {
      cmd = "netstat";
      args = ["-an"];
    }

    const child = spawn(cmd, args);
    let output = "";

    child.stdout.on("data", (data) => {
      output += data.toString();
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`Process exited with code ${code}`));
      }
    });
  });
}

ipcMain.handle("get-processes", async () => {
  try {
    return await getRunningProcesses();
  } catch (error) {
    return { error: error.message };
  }
});

ipcMain.handle("get-network", async () => {
  try {
    return await getNetworkConnections();
  } catch (error) {
    return { error: error.message };
  }
});

ipcMain.handle("get-system-info", () => {
  return {
    platform: os.platform(),
    arch: os.arch(),
    totalMemory: os.totalmem(),
    freeMemory: os.freemem(),
    cpus: os.cpus().length,
  };
});

ipcMain.handle("start-invisible-detection", () => {
  if (invisibleDetector) {
    invisibleDetector.startDeepMonitoring();
    return { success: true };
  }
  return { error: "Detector not initialized" };
});

ipcMain.handle("stop-invisible-detection", () => {
  if (invisibleDetector) {
    invisibleDetector.stopDeepMonitoring();
    return { success: true };
  }
  return { error: "Detector not initialized" };
});

ipcMain.handle("get-detection-report", () => {
  if (invisibleDetector) {
    return invisibleDetector.getDetectionReport();
  }
  return { error: "Detector not initialized" };
});

ipcMain.handle("clear-detection-history", () => {
  if (invisibleDetector) {
    invisibleDetector.clearHistory();
    return { success: true };
  }
  return { error: "Detector not initialized" };
});

ipcMain.handle("show-overlay", () => {
  if (overlayWindow) {
    overlayWindow.show();
    return { success: true };
  }
  return { error: "Overlay not initialized" };
});

ipcMain.handle("hide-overlay", () => {
  if (overlayWindow) {
    overlayWindow.hide();
    return { success: true };
  }
  return { error: "Overlay not initialized" };
});

ipcMain.handle("update-overlay-status", (event, status) => {
  if (overlayWindow) {
    overlayWindow.webContents.send("status-update", status);
    return { success: true };
  }
  return { error: "Overlay not initialized" };
});

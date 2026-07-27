const path = require("path");
const http = require("http");
const express = require("express");
const { Server } = require("socket.io");
const net = require("net");
const fs = require("fs");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const GATEWAY_IP =
  process.env.GATEWAY_IP || process.env.MODBUS_TARGET_IP || "10.10.20.77";
const GATEWAY_PORT =
  parseInt(process.env.GATEWAY_PORT || process.env.MODBUS_TARGET_PORT, 10) ||
  502;
const PORT = parseInt(process.env.PORT || process.env.HTTP_PORT, 10) || 3000;
const MAPPING_FILE = path.join(__dirname, "mapping_backup.json");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let registerMappings = {};
let transactions = [];
let errors = [];
let pendingRequests = new Map();

let clientSocket = null;
let buffer = Buffer.alloc(0);
let isRunning = true;
let isConnected = false;

if (fs.existsSync(MAPPING_FILE)) {
  try {
    registerMappings = JSON.parse(fs.readFileSync(MAPPING_FILE, "utf8"));
    console.log("📁 Mapping-Datei erfolgreich geladen.");
  } catch (e) {
    console.error("❌ Fehler beim Laden der Mapping-Datei:", e.message);
  }
}

function saveMappingsToFile() {
  try {
    fs.writeFileSync(MAPPING_FILE, JSON.stringify(registerMappings, null, 2));
  } catch (e) {
    console.error("❌ Fehler beim Speichern der Mapping-Datei:", e.message);
  }
}

const functionNames = {
  1: "Read Coils (0x)",
  2: "Read Discrete Inputs (1x)",
  3: "Read Holding Registers (4x)",
  4: "Read Input Registers (3x)",
  5: "Write Single Coil",
  6: "Write Single Register",
  15: "Write Multiple Coils",
  16: "Write Multiple Registers",
};

function checkCRC(buf) {
  if (buf.length < 4) return false;
  let crc = 0xffff;
  for (let pos = 0; pos < buf.length - 2; pos++) {
    crc ^= buf[pos];
    for (let i = 8; i !== 0; i--) {
      if ((crc & 0x0001) !== 0) {
        crc >>= 1;
        crc ^= 0xa001;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc === buf.readUInt16LE(buf.length - 2);
}

function parseRtuFrames(chunk) {
  if (!isRunning) return;
  buffer = Buffer.concat([buffer, chunk]);

  if (buffer.length > 2048) {
    buffer = buffer.slice(buffer.length - 1024);
  }

  while (buffer.length >= 5) {
    const slaveId = buffer[0];
    const funcCode = buffer[1];
    let expectedLength = -1;

    if ([1, 2, 3, 4, 5, 6].includes(funcCode) && buffer.length >= 8) {
      if (checkCRC(buffer.slice(0, 8))) expectedLength = 8;
    }
    if (
      expectedLength === -1 &&
      [1, 2, 3, 4].includes(funcCode) &&
      buffer.length >= 3
    ) {
      const byteCount = buffer[2];
      const respLen = 3 + byteCount + 2;
      if (buffer.length >= respLen && byteCount < 250) {
        if (checkCRC(buffer.slice(0, respLen))) expectedLength = respLen;
      }
    }
    if (
      expectedLength === -1 &&
      [15, 16].includes(funcCode) &&
      buffer.length >= 7
    ) {
      const byteCount = buffer[6];
      const reqLen = 7 + byteCount + 2;
      if (buffer.length >= reqLen) {
        if (checkCRC(buffer.slice(0, reqLen))) expectedLength = reqLen;
      }
    }

    if (expectedLength === -1 || expectedLength > 256) {
      buffer = buffer.slice(1);
      continue;
    }

    if (buffer.length >= expectedLength) {
      const frame = buffer.slice(0, expectedLength);
      buffer = buffer.slice(expectedLength);

      if (checkCRC(frame)) {
        processValidFrame(slaveId, funcCode, frame);
      } else {
        errors.unshift({
          timestamp: new Date().toISOString(),
          slaveId: String(slaveId),
          errorType: "CRC-Fehler",
          details: frame.toString("hex").toUpperCase(),
        });
        if (errors.length > 50) errors.pop();
        broadcastUpdate();
      }
    } else {
      break;
    }
  }
}

function processValidFrame(slaveId, funcCode, frame) {
  const timestamp = new Date().toISOString();
  const funcName = functionNames[funcCode] || `Unknown (${funcCode})`;

  const isRequest =
    ([1, 2, 3, 4, 5, 6].includes(funcCode) && frame.length === 8) ||
    ([15, 16].includes(funcCode) &&
      frame.length > 8 &&
      frame[2] !== frame.length - 9);

  if (isRequest) {
    let startReg = 0;
    let countOrVal = 0;
    if ([1, 2, 3, 4, 5, 6].includes(funcCode)) {
      startReg = frame.readUInt16BE(2);
      countOrVal = frame.readUInt16BE(4);
    }

    const isWrite = [5, 6, 15, 16].includes(funcCode);
    if (isWrite) {
      io.emit("writePopup", {
        timestamp,
        slaveId,
        funcCode,
        funcName,
        startReg,
        value: countOrVal,
        raw: frame.toString("hex").toUpperCase(),
      });

      const regKey = `${slaveId}-${startReg}`;
      if (!registerMappings[regKey]) {
        registerMappings[regKey] = {
          slaveId,
          regNum: startReg,
          labels: { name: `Reg ${startReg}`, unit: "", multiplier: 1 },
        };
      }
      registerMappings[regKey].lastWrittenValue = countOrVal;
      registerMappings[regKey].currentValue = countOrVal;
      registerMappings[regKey].timestamp = timestamp;
      sortAndSaveMappings();
    }

    const tx = {
      id: String(Date.now() + Math.random()),
      timestamp,
      slaveId,
      funcCode,
      funcName,
      type: isWrite ? "Write" : "Request",
      startReg: String(startReg),
      countOrVal: String(countOrVal),
      raw: frame.toString("hex").toUpperCase(),
    };

    transactions.unshift(tx);
    if (transactions.length > 100) transactions.pop();
    pendingRequests.set(`${slaveId}-${funcCode}`, tx);
    broadcastUpdate();
  } else {
    const pendingKey = `${slaveId}-${funcCode}`;
    let tx = pendingRequests.get(pendingKey);
    let startReg = tx ? parseInt(tx.startReg, 10) : 0;

    if ([1, 2, 3, 4].includes(funcCode) && frame.length >= 5) {
      const byteCount = frame[2];
      const regBuffer = frame.slice(3, 3 + byteCount);

      for (let i = 0; i < regBuffer.length; i += 2) {
        if (i + 1 < regBuffer.length) {
          const raw = regBuffer.readUInt16BE(i);
          const currentReg = startReg + i / 2;

          const regKey = `${slaveId}-${currentReg}`;
          if (!registerMappings[regKey]) {
            registerMappings[regKey] = {
              slaveId,
              regNum: currentReg,
              labels: { name: `Reg ${currentReg}`, unit: "", multiplier: 1 },
            };
          }
          registerMappings[regKey].currentValue = raw;
          registerMappings[regKey].timestamp = timestamp;
        }
      }
      sortAndSaveMappings();
    }

    const newTx = {
      id: String(Date.now() + Math.random()),
      timestamp,
      slaveId,
      funcCode,
      funcName,
      type: "Response",
      startReg: tx ? tx.startReg : "?",
      countOrVal: "-",
      raw: frame.toString("hex").toUpperCase(),
    };

    transactions.unshift(newTx);
    if (transactions.length > 100) transactions.pop();
    pendingRequests.delete(pendingKey);
    broadcastUpdate();
  }
}

// Hilfsfunktion: Sortiert Mappings (gemappte nach oben) und speichert sie ab
function sortAndSaveMappings() {
  const sortedKeys = Object.keys(registerMappings).sort((a, b) => {
    const regA = registerMappings[a];
    const regB = registerMappings[b];

    const isMappedA =
      regA.labels && regA.labels.name && !regA.labels.name.startsWith("Reg ");
    const isMappedB =
      regB.labels && regB.labels.name && !regB.labels.name.startsWith("Reg ");
    const hasWriteLabelsA =
      regA.writeLabels && Object.keys(regA.writeLabels).length > 0;
    const hasWriteLabelsB =
      regB.writeLabels && Object.keys(regB.writeLabels).length > 0;

    const scoreA = isMappedA || hasWriteLabelsA ? 1 : 0;
    const scoreB = isMappedB || hasWriteLabelsB ? 1 : 0;

    // Höherer Score (gemappt) kommt nach oben (-1)
    if (scoreA !== scoreB) {
      return scoreB - scoreA;
    }
    // Ansonsten nach Slave-ID und Registernummer sortieren
    if (regA.slaveId !== regB.slaveId) {
      return regA.slaveId - regB.slaveId;
    }
    return regA.regNum - regB.regNum;
  });

  const sortedObj = {};
  for (const key of sortedKeys) {
    sortedObj[key] = registerMappings[key];
  }
  registerMappings = sortedObj;
  saveMappingsToFile();
}

function connectGateway() {
  console.log(
    `Verbinde direkt mit USR-Gateway ${GATEWAY_IP}:${GATEWAY_PORT} ...`,
  );
  clientSocket = new net.Socket();

  clientSocket.connect(GATEWAY_PORT, GATEWAY_IP, () => {
    isConnected = true;
    console.log(
      `✅ Erfolgreich verbunden mit USR-Gateway ${GATEWAY_IP}:${GATEWAY_PORT}`,
    );
    broadcastUpdate();
  });

  clientSocket.on("data", (chunk) => {
    parseRtuFrames(chunk);
  });

  clientSocket.on("close", () => {
    isConnected = false;
    console.log(
      "⚠️ Verbindung zum Gateway getrennt. Neuer Versuch in 5 Sek...",
    );
    broadcastUpdate();
    clientSocket.destroy();
    setTimeout(connectGateway, 5000);
  });

  clientSocket.on("error", (err) => {
    isConnected = false;
    console.error("❌ Socket Fehler:", err.message);
    broadcastUpdate();
    clientSocket.destroy();
  });
}

function broadcastUpdate() {
  io.emit("updateData", {
    transactions,
    registers: registerMappings,
    errors,
    isRunning,
    isConnected,
  });
}

io.on("connection", (socket) => {
  broadcastUpdate();

  socket.on("start", () => {
    isRunning = true;
    broadcastUpdate();
  });
  socket.on("stop", () => {
    isRunning = false;
    broadcastUpdate();
  });

  socket.on("clear", () => {
    transactions = [];
    errors = [];
    registerMappings = {};
    if (fs.existsSync(MAPPING_FILE)) fs.unlinkSync(MAPPING_FILE);
    pendingRequests.clear();
    broadcastUpdate();
  });

  socket.on(
    "updateRegisterMapping",
    ({ regKey, name, unit, multiplier, writeLabels }) => {
      if (!registerMappings[regKey]) {
        const parts = regKey.split("-");
        registerMappings[regKey] = {
          slaveId: parseInt(parts[0], 10),
          regNum: parseInt(parts[1], 10),
        };
      }
      registerMappings[regKey].labels = {
        name,
        unit,
        multiplier: parseFloat(multiplier) || 1,
      };
      if (writeLabels) {
        registerMappings[regKey].writeLabels = writeLabels;
      }
      sortAndSaveMappings();
      broadcastUpdate();
    },
  );

  socket.on("restoreMappings", (importedMappings) => {
    if (importedMappings && typeof importedMappings === "object") {
      registerMappings = importedMappings;
      sortAndSaveMappings();
      broadcastUpdate();
    }
  });
});

app.get("/api/backup", (req, res) => {
  res.download(MAPPING_FILE, "modbus_mapping_backup.json");
});

server.listen(PORT, () => {
  console.log(`🚀 Web-UI läuft unter: http://localhost:${PORT}`);
  connectGateway();
});

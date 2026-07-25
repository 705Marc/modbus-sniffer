const path = require("path");
const http = require("http");
const express = require("express");
const { Server } = require("socket.io");
const net = require("net");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const GATEWAY_IP = process.env.GATEWAY_IP || "10.10.20.77";
const GATEWAY_PORT = parseInt(process.env.GATEWAY_PORT, 10) || 502;
const PORT = parseInt(process.env.PORT, 10) || 3000;

app.use(express.static(path.join(__dirname, "public")));

let transactions = [];
let errors = []; // 24/7 Schutz: Fehler-Array für den Fehler-Monitor
let pendingRequests = new Map();
let activeRegisters = new Map();
const MAX_ACTIVE_REGISTERS = 2000; // 24/7 Schutz: Begrenzung der maximal gespeicherten Register im RAM

let clientSocket = null;
let buffer = Buffer.alloc(0);

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
  const receivedCrc = buf.readUInt16LE(buf.length - 2);
  return crc === receivedCrc;
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

// Hilfsfunktion zur sicheren Begrenzung von Maps im 24/7 Betrieb
function setSafeRegister(key, value) {
  if (
    activeRegisters.size >= MAX_ACTIVE_REGISTERS &&
    !activeRegisters.has(key)
  ) {
    // Lösche den ältesten Eintrag (das erste Element der Map)
    const oldestKey = activeRegisters.keys().next().value;
    activeRegisters.delete(oldestKey);
  }
  activeRegisters.set(key, value);
}

function parseRtuFrames(chunk) {
  buffer = Buffer.concat([buffer, chunk]);

  // Schutz vor unendlichem Aufwachsen des rohen Byte-Buffers bei Bus-Störungen
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
        // CRC-Fehler protokollieren für den Fehler-Monitor
        errors.push({
          timestamp: new Date().toISOString(),
          slaveId,
          errorType: "CRC-Fehler",
          details: frame.toString("hex").toUpperCase(),
        });
        if (errors.length > 100) errors.shift();
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

    if (funcCode === 6) {
      const regKey = `${slaveId}-${startReg}`;
      setSafeRegister(regKey, {
        slaveId,
        regNum: startReg,
        raw: countOrVal,
        signed: countOrVal > 32767 ? countOrVal - 65536 : countOrVal,
        timestamp,
        funcCode,
        type: "Write Single",
      });
    }

    const tx = {
      id: Date.now() + Math.random(),
      timestamp,
      slaveId,
      funcCode,
      funcName,
      type: "Request",
      startReg,
      countOrVal,
      requestRaw: frame.toString("hex").toUpperCase(),
      responseValues: "Warte auf Antwort...",
      status: "pending",
    };

    transactions.unshift(tx);
    if (transactions.length > 100) transactions.pop(); // Max 100 Transaktionen

    pendingRequests.set(`${slaveId}-${funcCode}`, tx);
    broadcastUpdate();
  } else {
    const pendingKey = `${slaveId}-${funcCode}`;
    let tx = pendingRequests.get(pendingKey);

    let decodedValues = [];
    let startReg = tx ? tx.startReg : 0;

    if ([1, 2, 3, 4].includes(funcCode) && frame.length >= 5) {
      const byteCount = frame[2];
      const regBuffer = frame.slice(3, 3 + byteCount);

      for (let i = 0; i < regBuffer.length; i += 2) {
        if (i + 1 < regBuffer.length) {
          const raw = regBuffer.readUInt16BE(i);
          const signed = raw > 32767 ? raw - 65536 : raw;
          const currentReg = startReg + i / 2;

          let uint32_ABCD = null;
          let float_ABCD = null;

          if (i + 3 < regBuffer.length) {
            const nextRaw = regBuffer.readUInt16BE(i + 2);
            uint32_ABCD = raw * 65536 + nextRaw;

            const bufFloat = Buffer.alloc(4);
            bufFloat.writeUInt16BE(raw, 0);
            bufFloat.writeUInt16BE(nextRaw, 2);
            float_ABCD = bufFloat.readFloatBE(0);
          }

          const decVal = {
            raw,
            signed,
            uint32_ABCD,
            float_ABCD:
              float_ABCD !== null && !isNaN(float_ABCD) && isFinite(float_ABCD)
                ? Number(float_ABCD.toFixed(4))
                : null,
          };

          decodedValues.push(decVal);

          // Sicherer Eintrag in die Register-Map mit Größenlimit
          setSafeRegister(`${slaveId}-${currentReg}`, {
            slaveId,
            regNum: currentReg,
            ...decVal,
            timestamp,
            funcCode,
            type: "Read",
          });
        }
      }
    }

    if (tx) {
      tx.responseRaw = frame.toString("hex").toUpperCase();
      tx.decodedValues = decodedValues;
      tx.status = "completed";
      pendingRequests.delete(pendingKey);
    } else {
      transactions.unshift({
        id: Date.now() + Math.random(),
        timestamp,
        slaveId,
        funcCode,
        funcName,
        type: "ResponseOnly",
        startReg: "?",
        countOrVal: "?",
        requestRaw: "-",
        responseRaw: frame.toString("hex").toUpperCase(),
        decodedValues: decodedValues,
        status: "completed",
      });
      if (transactions.length > 100) transactions.pop();
    }

    broadcastUpdate();
  }
}

function broadcastUpdate() {
  const registersArray = Array.from(activeRegisters.values());
  io.emit("updateData", { transactions, registers: registersArray, errors });
}

function connectGateway() {
  console.log(`Verbinde mit Gateway ${GATEWAY_IP}:${GATEWAY_PORT} ...`);
  clientSocket = new net.Socket();

  clientSocket.connect(GATEWAY_PORT, GATEWAY_IP, () => {
    console.log(`✅ Verbunden mit USR-Gateway ${GATEWAY_IP}:${GATEWAY_PORT}`);
  });

  clientSocket.on("data", (chunk) => {
    parseRtuFrames(chunk);
  });

  clientSocket.on("close", () => {
    console.log("⚠️ Verbindung getrennt. Neuer Versuch in 5 Sek...");
    clientSocket.destroy();
    setTimeout(connectGateway, 5000);
  });

  clientSocket.on("error", (err) => {
    console.error("❌ Socket Fehler:", err.message);
    errors.push({
      timestamp: new Date().toISOString(),
      slaveId: "-",
      errorType: "Socket-Fehler",
      details: err.message,
    });
    if (errors.length > 100) errors.shift();
    clientSocket.destroy();
  });
}

io.on("connection", (socket) => {
  socket.emit("updateData", {
    transactions,
    registers: Array.from(activeRegisters.values()),
    errors,
  });

  socket.on("clear", () => {
    transactions = [];
    errors = [];
    pendingRequests.clear();
    activeRegisters.clear();
    broadcastUpdate();
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Modbus Sniffer läuft unter: http://localhost:${PORT}`);
  connectGateway();
});

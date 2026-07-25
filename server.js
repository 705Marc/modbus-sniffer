const path = require("path");
const http = require("http");
const express = require("express");
const { Server } = require("socket.io");
const net = require("net");
const Database = require("better-sqlite3");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const GATEWAY_IP = process.env.GATEWAY_IP || "10.10.20.77";
const GATEWAY_PORT = parseInt(process.env.GATEWAY_PORT, 10) || 502;
const PORT = parseInt(process.env.PORT, 10) || 3000;
// Speicherzeit in Stunden aus .env (Standard: 24 Stunden, wenn nicht angegeben)
const RETENTION_HOURS = parseInt(process.env.RETENTION_HOURS, 10) || 24;

app.use(express.static(path.join(__dirname, "public")));

// --- SQLite Datenbank initialisieren ---
const db = new Database(path.join(__dirname, "modbus_sniffer.db"));

// Tabellen erstellen, falls sie noch nicht existieren
db.exec(`
  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    slaveId INTEGER,
    funcCode INTEGER,
    funcName TEXT,
    type TEXT,
    startReg TEXT,
    countOrVal TEXT,
    requestRaw TEXT,
    responseRaw TEXT,
    decodedValues TEXT,
    status TEXT
  );

  CREATE TABLE IF NOT EXISTS registers (
    regKey TEXT PRIMARY KEY,
    slaveId INTEGER,
    regNum INTEGER,
    raw INTEGER,
    signed INTEGER,
    uint32_ABCD INTEGER,
    float_ABCD REAL,
    timestamp TEXT,
    funcCode INTEGER,
    type TEXT
  );

  CREATE TABLE IF NOT EXISTS errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    slaveId TEXT,
    errorType TEXT,
    details TEXT
  );
`);

// Prepared Statements für maximale Performance
const insertTransactionStmt = db.prepare(`
  INSERT OR REPLACE INTO transactions (id, timestamp, slaveId, funcCode, funcName, type, startReg, countOrVal, requestRaw, responseRaw, decodedValues, status)
  VALUES (@id, @timestamp, @slaveId, @funcCode, @funcName, @type, @startReg, @countOrVal, @requestRaw, @responseRaw, @decodedValues, @status)
`);

const insertRegisterStmt = db.prepare(`
  INSERT OR REPLACE INTO registers (regKey, slaveId, regNum, raw, signed, uint32_ABCD, float_ABCD, timestamp, funcCode, type)
  VALUES (@regKey, @slaveId, @regNum, @raw, @signed, @uint32_ABCD, @float_ABCD, @timestamp, @funcCode, @type)
`);

const insertErrorStmt = db.prepare(`
  INSERT INTO errors (timestamp, slaveId, errorType, details)
  VALUES (@timestamp, @slaveId, @errorType, @details)
`);

const clearDbStmt = db.transaction(() => {
  db.prepare("DELETE FROM transactions").run();
  db.prepare("DELETE FROM registers").run();
  db.prepare("DELETE FROM errors").run();
});
// ----------------------------------------

let pendingRequests = new Map();
const MAX_ACTIVE_REGISTERS = 2000; // 24/7 Schutz: Begrenzung

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

// Hilfsfunktion zur sicheren Begrenzung von Registern in SQLite
function setSafeRegister(regKey, data) {
  const countRow = db.prepare("SELECT COUNT(*) as count FROM registers").get();
  if (countRow.count >= MAX_ACTIVE_REGISTERS) {
    db.prepare(
      "DELETE FROM registers WHERE regKey = (SELECT regKey FROM registers ORDER BY timestamp ASC LIMIT 1)",
    ).run();
  }
  insertRegisterStmt.run({ regKey, ...data });
}

function parseRtuFrames(chunk) {
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
        const errData = {
          timestamp: new Date().toISOString(),
          slaveId: String(slaveId),
          errorType: "CRC-Fehler",
          details: frame.toString("hex").toUpperCase(),
        };
        insertErrorStmt.run(errData);
        // Begrenze Fehlertabelle auf max 100 Einträge
        db.prepare(
          "DELETE FROM errors WHERE id NOT IN (SELECT id FROM errors ORDER BY id DESC LIMIT 100)",
        ).run();
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
        uint32_ABCD: null,
        float_ABCD: null,
        timestamp,
        funcCode,
        type: "Write Single",
      });
    }

    const tx = {
      id: String(Date.now() + Math.random()),
      timestamp,
      slaveId,
      funcCode,
      funcName,
      type: "Request",
      startReg: String(startReg),
      countOrVal: String(countOrVal),
      requestRaw: frame.toString("hex").toUpperCase(),
      responseRaw: "Warte auf Antwort...",
      decodedValues: JSON.stringify([]),
      status: "pending",
    };

    insertTransactionStmt.run(tx);

    pendingRequests.set(`${slaveId}-${funcCode}`, tx);
    broadcastUpdate();
  } else {
    const pendingKey = `${slaveId}-${funcCode}`;
    let tx = pendingRequests.get(pendingKey);

    let decodedValues = [];
    let startReg = tx ? parseInt(tx.startReg, 10) : 0;

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

          setSafeRegister(`${slaveId}-${currentReg}`, {
            slaveId,
            regNum: currentReg,
            raw: decVal.raw,
            signed: decVal.signed,
            uint32_ABCD: decVal.uint32_ABCD,
            float_ABCD: decVal.float_ABCD,
            timestamp,
            funcCode,
            type: "Read",
          });
        }
      }
    }

    if (tx) {
      tx.responseRaw = frame.toString("hex").toUpperCase();
      tx.decodedValues = JSON.stringify(decodedValues);
      tx.status = "completed";
      insertTransactionStmt.run(tx);
      pendingRequests.delete(pendingKey);
    } else {
      const newTx = {
        id: String(Date.now() + Math.random()),
        timestamp,
        slaveId,
        funcCode,
        funcName,
        type: "ResponseOnly",
        startReg: "?",
        countOrVal: "?",
        requestRaw: "-",
        responseRaw: frame.toString("hex").toUpperCase(),
        decodedValues: JSON.stringify(decodedValues),
        status: "completed",
      };
      insertTransactionStmt.run(newTx);
    }

    broadcastUpdate();
  }
}

// Hilfsfunktion: Löscht Transaktionen und Fehler, die älter sind als RETENTION_HOURS
function cleanupDatabase() {
  const cutoffTime = new Date(
    Date.now() - RETENTION_HOURS * 3600 * 1000,
  ).toISOString();

  db.prepare(`DELETE FROM transactions WHERE timestamp < ?`).run(cutoffTime);
  db.prepare(`DELETE FROM errors WHERE timestamp < ?`).run(cutoffTime);
}

function getDatabaseData() {
  const transactions = db
    .prepare("SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 100")
    .all()
    .map((tx) => ({
      ...tx,
      decodedValues: tryParseJSON(tx.decodedValues),
    }));

  const registers = db.prepare("SELECT * FROM registers").all();
  const errors = db
    .prepare("SELECT * FROM errors ORDER BY timestamp DESC LIMIT 100")
    .all();

  return { transactions, registers, errors };
}

function tryParseJSON(str) {
  try {
    return JSON.parse(str);
  } catch (e) {
    return [];
  }
}

function broadcastUpdate() {
  const data = getDatabaseData();
  io.emit("updateData", data);
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
    insertErrorStmt.run({
      timestamp: new Date().toISOString(),
      slaveId: "-",
      errorType: "Socket-Fehler",
      details: err.message,
    });
    db.prepare(
      "DELETE FROM errors WHERE id NOT IN (SELECT id FROM errors ORDER BY id DESC LIMIT 100)",
    ).run();
    clientSocket.destroy();
  });
}

io.on("connection", (socket) => {
  socket.emit("updateData", getDatabaseData());

  socket.on("clear", () => {
    clearDbStmt();
    pendingRequests.clear();
    broadcastUpdate();
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Modbus Sniffer läuft unter: http://localhost:${PORT}`);

  // Beim Start einmalig aufräumen und dann alle 15 Minuten im Hintergrund
  cleanupDatabase();
  setInterval(cleanupDatabase, 15 * 60 * 1000);

  connectGateway();
});

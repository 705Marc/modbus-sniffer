# Modbus RTU Bus-Monitor & Matrix

Ein moderner, webbasierter Echtzeit-Bus-Monitor und Analyzer für Modbus RTU, entwickelt mit Node.js, Express, Socket.io und einer responsiven Frontend-Oberfläche (inklusive Chart.js für Live-Trends).

---

## 🚀 Features

1. **Live Bus-Log (Chronologisch):**
   - Verfolgt alle Modbus-Telegramme in Echtzeit.
   - Automatische Dekodierung von Registern (16-Bit Signed/Unsigned, 32-Bit Integer sowie Float-Werte in den gängigen Byte-Reihenfolgen `AB` und `CD`).
   - **Funktions-Filter:** Gezieltes Filtern nach einzelnen Modbus-Funktionscodes (z. B. _FC 03 - Read Holding Registers_).
   - Lokale Zeitzone mit genauer Datums- und Uhrzeitanzeige.

2. **Register-Matrix (Übersicht):**
   - Grafische Rasteransicht aller aktiv abgefragten Register.
   - Paginierung / Block-Ansicht (in 1000er-Schritten) zur schnellen Orientierung in großen Registerbereichen.
   - Slave-ID-Filter.
   - Detail-Tooltips mit Rohwerten, Vorzeichen und Zeitstempeln per Mouseover.

3. **Register-Live-Trend (Chart):**
   - Visuelle Echtzeit-Diagramme (Oszilloskop-Ansicht) über **Chart.js**.
   - Einfaches Verfolgen ausgewählter Register im Zeitverlauf durch kommagetrennte Eingabe (z. B. `100, 102, 305`), um Sensor- oder Aktoränderungen sofort zuzuordnen.

4. **Änderungs-Monitor (Diff):**
   - Filtert das Grundrauschen des Busses komplett weg.
   - Zeigt **ausschließlich** Register an, deren Werte sich im Vergleich zur vorherigen Abfrage verändert haben (inklusive Vorher/Nachher-Wert und Zeitstempel).

5. **Export & Verwaltung:**
   - CSV-Export der aufgezeichneten Transaktionen.
   - Funktion zum Zurücksetzen der Daten per Button.

---

## 🛠️ Installation & Start (Docker Setup)

### 1. Repository vorbereiten

Stelle sicher, dass **Docker** und **Docker Compose** auf deinem System installiert sind.

### 2. `.env`-Datei erstellen

Erstelle im Projektverzeichnis eine `.env`-Datei, um Umgebungsvariablen (wie z. B. den Port) zu definieren:

```env
GATEWAY_IP=DEINE_IP
GATEWAY_PORT=502
PORT=3000
```

### 3. Docker Container Starten

```bash
docker compose up -d --build
```

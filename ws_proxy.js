// ws_proxy.js
//
// WebSocket ↔ TCP bridge
// - Listens on ws://localhost:8080 for browser clients
// - Connects to your C chat server on 127.0.0.1:9090
// - Forwards data both ways
//
// Usage:
//   node ws_proxy.js

const net = require("net");
const WebSocket = require("ws");

// TCP connection to your C chat server
const TCP_HOST = "127.0.0.1";
const TCP_PORT = 9090;

// WebSocket server for browser clients
const wss = new WebSocket.Server({ port: 8080 });

console.log(`WebSocket bridge running on ws://localhost:8080 (TCP → ${TCP_HOST}:${TCP_PORT})`);

wss.on("connection", (ws) => {
    console.log("🟢 Browser connected to WebSocket bridge.");

    // Open TCP connection to C chat server
    const tcp = net.createConnection({ host: TCP_HOST, port: TCP_PORT }, () => {
        console.log("🔌 Connected to TCP chat server.");
    });

    // Browser → TCP server
    ws.on("message", (data) => {
        let msg = data.toString();
        // Ensure messages end with newline so C server's recv+trim works
        if (!msg.endsWith("\n")) {
            msg += "\n";
        }
        tcp.write(msg);
    });

    // TCP server → Browser
    tcp.on("data", (chunk) => {
        const text = chunk.toString();
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(text);
        }
    });

    tcp.on("close", () => {
        console.log("🔴 TCP connection closed.");
        if (ws.readyState === WebSocket.OPEN) {
            ws.close();
        }
    });

    tcp.on("error", (err) => {
        console.error("TCP error:", err.message);
        if (ws.readyState === WebSocket.OPEN) {
            ws.send("[System] TCP error: " + err.message);
            ws.close();
        }
    });

    ws.on("close", () => {
        console.log("🔴 Browser WebSocket disconnected.");
        tcp.destroy();
    });

    ws.on("error", (err) => {
        console.error("WebSocket error:", err.message);
        tcp.destroy();
    });
});

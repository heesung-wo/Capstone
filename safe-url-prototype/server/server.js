"use strict";
const http = require("node:http");
const { scan } = require("./scan");

function createServer(scanner = scan) {
  return http.createServer(async (req, res) => {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    if (req.method === "GET" && req.url === "/health") { res.writeHead(200); res.end(JSON.stringify({ ok: true })); return; }
    if (req.method !== "POST" || req.url !== "/scan") { res.writeHead(404); res.end(JSON.stringify({ error: "Not found" })); return; }
    const origin = req.headers.origin;
    if (origin && !/^chrome-extension:\/\/[a-p]{32}$/.test(origin)) {
      res.writeHead(403); res.end(JSON.stringify({ error: "Extension origin required" })); return;
    }
    if (req.headers["content-type"]?.split(";")[0] !== "application/json") {
      res.writeHead(415); res.end(JSON.stringify({ error: "JSON required" })); return;
    }
    try {
      let body = "";
      for await (const chunk of req) { body += chunk; if (body.length > 8192) throw new Error("요청이 너무 큽니다."); }
      const input = JSON.parse(body);
      const result = await scanner(input.url);
      res.writeHead(200); res.end(JSON.stringify(result));
    } catch (error) {
      res.writeHead(400); res.end(JSON.stringify({ error: error.message }));
    }
  });
}
if (require.main === module) {
  createServer().listen(3000, "127.0.0.1", () => console.log("Safe UR Link server: http://127.0.0.1:3000"));
}
module.exports = { createServer };

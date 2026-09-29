"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { scan, normalizeUrl } = require("./scan");
const { createServer } = require("./server");

test("verified valid phish is malicious and scored 40/40", async () => {
  const fetchMock = async (_endpoint, options) => {
    assert.equal(options.method, "POST");
    assert.equal(new URLSearchParams(options.body).get("url"), "https://example.test/login");
    return { ok: true, json: async () => ({ results: { in_database: true, verified: "y", valid: "y" } }) };
  };
  const result = await scan("https://example.test/login", fetchMock);
  assert.equal(result.status, "MALICIOUS");
  assert.equal(result.sources.phishTank.score, 40);
});

test("failed API is unverified rather than safe; verified false positive is zero", async () => {
  const failed = await scan("https://example.test/", async () => { throw Error("offline"); });
  assert.equal(failed.status, "UNVERIFIED");
  assert.equal(failed.sources.phishTank.available, false);
  const cleared = await scan("https://example.test/", async () => ({ ok: true, json: async () => ({ results: { in_database: true, verified: "y", valid: "n" } }) }));
  assert.equal(cleared.sources.phishTank.score, 0);
  assert.equal(cleared.status, "UNKNOWN");
});

test("rejects schemes and credentials before sending URL", () => {
  assert.throws(() => normalizeUrl("file:///secret.txt"));
  assert.throws(() => normalizeUrl("https://user:password@example.com"));
});

test("localhost HTTP route returns scanner JSON", async () => {
  const server = createServer(async url => ({ url, status: "UNKNOWN" }));
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    const port = server.address().port;
    const response = await fetch(`http://127.0.0.1:${port}/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: "https://example.test" }) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, "UNKNOWN");
  } finally { server.close(); }
});

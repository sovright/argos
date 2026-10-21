const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunction(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return vm.runInNewContext(`${source.slice(start, end + 3)}; ${name}`, {});
}

const scanStatusFields = loadFunction("scanStatusFields");
const PRIMARY = "https://zec.rocks:443";
const warmup = { kind: "warmup" };

// The shape a transparent-only wallet.dat scan finishes with: no block scan,
// so no server, no block counts, but a synced_to_height at the chain tip.
const transparentOnlyComplete = {
  phase: "complete",
  server: null,
  blocks_scanned: 0,
  blocks_total: 0,
  synced_to_height: 3523736,
};

test("a finished scan with no block scan shows no placeholders", () => {
  const f = scanStatusFields(transparentOnlyComplete, warmup, "2026", PRIMARY);
  assert.equal(f.terminal, true);
  assert.equal(f.server, "—", "must not stay on Connecting…");
  assert.equal(f.progressText, "—", "must not read 0 / 0");
  assert.equal(f.etaText, "", "no Calculating… and no era hint once finished");
  assert.equal(f.barPercent, 100);
});

test("a finished block scan keeps the server it used", () => {
  const f = scanStatusFields(
    { phase: "complete", server: { endpoint: PRIMARY }, blocks_scanned: 1000, blocks_total: 1000, synced_to_height: 3500000 },
    { kind: "done" },
    "2026",
    PRIMARY,
  );
  assert.equal(f.server, PRIMARY);
  assert.equal(f.progressText, "1,000 / 1,000");
  assert.equal(f.etaText, "");
});

test("a running block scan keeps its live fields", () => {
  const f = scanStatusFields(
    {
      phase: "scanning",
      server: { endpoint: PRIMARY },
      blocks_scanned: 500,
      blocks_total: 1000,
      synced_to_height: 1500000,
    },
    { kind: "estimate", text: "5m" },
    "2021",
    PRIMARY,
  );
  assert.equal(f.terminal, false);
  assert.equal(f.server, PRIMARY);
  assert.equal(f.serverTitle, "");
  assert.equal(f.progressText, "500 / 1,000");
  assert.equal(f.barPercent, 50);
  assert.equal(f.etaText, "5m · scanning ~2021");
});

test("before the server is known, a running scan leaves the placeholder alone", () => {
  const f = scanStatusFields(
    { phase: "scanning_transparent", server: null, blocks_scanned: 0, blocks_total: 0 },
    warmup,
    null,
    PRIMARY,
  );
  assert.equal(f.server, null);
  assert.equal(f.progressText, "0 / 0");
  assert.equal(f.etaText, "Calculating…");
});

test("a fallback server is labelled", () => {
  const f = scanStatusFields(
    { phase: "scanning", server: { endpoint: "https://na.zec.rocks:443" }, blocks_scanned: 1, blocks_total: 2 },
    warmup,
    null,
    PRIMARY,
  );
  assert.equal(f.server, "https://na.zec.rocks:443 (fallback)");
  assert.match(f.serverTitle, /fallback server/);
});

test("a cancelled scan keeps its counts and does not jump the bar to full", () => {
  const f = scanStatusFields(
    { phase: "cancelled", server: { endpoint: PRIMARY }, blocks_scanned: 10, blocks_total: 40 },
    warmup,
    "2019",
    PRIMARY,
  );
  assert.equal(f.progressText, "10 / 40");
  assert.equal(f.barPercent, 25);
  assert.equal(f.etaText, "");
});

test("the discovery toast marks its still-running note for removal", () => {
  assert.match(source, /className = "discovery-pending"/);
  assert.match(source, /\.discovery-pending"\)\.forEach\(\(el\) => el\.remove\(\)\)/);
});

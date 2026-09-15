const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { PUBLIC_MATCH, snapshot } = require("./address_search_fixture.cjs");

function harness(invoke) {
  class ClassList {
    constructor(owner) { this.owner = owner; }
    add(...names) { this.owner.className = [...new Set((this.owner.className + " " + names.join(" ")).trim().split(/\s+/))].join(" "); }
  }
  class Element {
    constructor(tag = "div") {
      this.tagName = tag.toUpperCase(); this.children = []; this.parentElement = null;
      this.listeners = {}; this.value = ""; this.textContent = ""; this.className = "";
      this.hidden = false; this.disabled = false; this.checked = false; this.style = {};
      this.classList = new ClassList(this);
    }
    append(...children) { for (const child of children) { child.parentElement = this; this.children.push(child); } }
    replaceChildren(...children) { this.children = []; this.append(...children); }
    remove() { if (this.parentElement) this.parentElement.children = this.parentElement.children.filter((child) => child !== this); }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    async fire(type) { for (const fn of this.listeners[type] || []) await fn({ preventDefault() {} }); }
    click() { return this.fire("click"); }
    focus() {}
    reset() {}
    setAttribute(name, value) { this[name] = value; }
    matches(selector) {
      return selector.split(",").some((part) => {
        const item = part.trim();
        if (item.startsWith(".")) return this.className.split(/\s+/).includes(item.slice(1));
        return this.tagName === item.toUpperCase();
      });
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    querySelectorAll(selector) { return this.children.flatMap((child) => [child.matches(selector) ? child : null, ...child.querySelectorAll(selector)]).filter(Boolean); }
  }
  const ids = [
    "address-search-modal", "address-search-form", "address-search-seeds", "address-search-progress", "address-search-results",
    "address-search-form-status", "address-search-target", "address-search-network", "address-search-account-start",
    "address-search-account-count", "address-search-index-start", "address-search-index-count", "address-search-change",
    "address-search-profile", "address-search-percent", "address-search-progress-bar", "address-search-count", "address-search-progress-title",
    "address-search-live-matches", "address-search-matches", "address-search-outcome", "address-search-limitation",
    "open-address-search", "close-address-search", "address-search-clear", "add-address-search-seed", "address-search-again",
    "address-search-new", "cancel-address-search", "start-address-search",
    "address-search-advanced", "address-search-profile-note",
  ];
  const elements = new Map(ids.map((id) => [id, new Element()]));
  elements.get("address-search-form").tagName = "FORM";
  const dispatched = [];
  const documentListeners = {};
  const document = {
    getElementById: (id) => elements.get(id),
    createElement: (tag) => new Element(tag),
    addEventListener: (type, fn) => {
      if (type === "DOMContentLoaded") fn();
      else (documentListeners[type] ||= []).push(fn);
    },
    dispatchEvent: (event) => {
      dispatched.push(event);
      for (const fn of documentListeners[event.type] || []) fn(event);
    },
  };
  class CustomEvent { constructor(type, options) { this.type = type; this.detail = options.detail; } }
  const timers = [];
  const window = {
    __TAURI__: { core: { invoke } }, addEventListener() {},
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: (id) => { if (id > 0) timers[id - 1] = null; },
  };
  vm.runInNewContext(fs.readFileSync("gui/src/address-search.js", "utf8"), {
    document, window, CustomEvent, console: { warn() {}, error() {} },
  });
  return {
    el: (id) => elements.get(id), dispatched,
    fireDocument: (type, detail = {}) => document.dispatchEvent(new CustomEvent(type, { detail })),
    runTimer: async () => {
      let fn = null;
      while (!fn && timers.length) fn = timers.shift();
      if (fn) await fn();
    },
  };
}

function fillValidForm(el) {
  el("open-address-search").fire("click");
  el("address-search-target").value = PUBLIC_MATCH.address;
  el("address-search-network").value = "mainnet";
  el("address-search-profile").value = "zecwallet_lite";
  el("address-search-account-start").value = "0";
  el("address-search-account-count").value = "1";
  el("address-search-index-start").value = "0";
  el("address-search-index-count").value = "20";
  el("address-search-change").checked = true;
  const row = el("address-search-seeds").children[0];
  row.querySelector(".candidate-seed-label").value = "Desk backup";
  row.querySelector(".candidate-seed-words").value = "synthetic words used only to test transient form state";
  row.querySelector(".candidate-seed-passphrase").value = "synthetic passphrase";
}

test("submits all scope fields, clears secrets, and renders an exact match", async () => {
  const calls = [];
  const { el } = harness(async (command, args) => {
    calls.push([command, args]);
    if (command === "start_address_search") return { id: "opaque-search-1" };
    if (command === "get_address_search") return snapshot();
    return null;
  });
  fillValidForm(el);
  await el("address-search-form").fire("submit");
  await new Promise(setImmediate);
  const input = calls.find(([command]) => command === "start_address_search")[1].input;
  assert.deepEqual(JSON.parse(JSON.stringify({ ...input, seeds: input.seeds.map(({ label }) => ({ label })) })), {
    target: PUBLIC_MATCH.address, network: "mainnet", seeds: [{ label: "Desk backup" }], profile: "zecwallet_lite",
    account_start: 0, account_count: 1, index_start: 0, index_count: 20, include_change: true,
  });
  assert.equal(el("address-search-seeds").children[0].querySelector(".candidate-seed-words").value, "");
  assert.equal(el("address-search-results").hidden, false, el("address-search-form-status").textContent);
  assert.match(el("address-search-outcome").children[0].textContent, /Exact match found/);
  assert.equal(el("address-search-matches").children[0].children[0].children[2].textContent, PUBLIC_MATCH.path);
  assert.match(el("address-search-limitation").textContent, /before making any network connection/);
});

test("recovery emits only opaque ids and public match metadata without releasing", async () => {
  const calls = [];
  const { el, dispatched } = harness(async (command) => {
    calls.push(command);
    if (command === "start_address_search") return { id: "opaque-search-1" };
    if (command === "get_address_search") return snapshot();
    return null;
  });
  fillValidForm(el);
  await el("address-search-form").fire("submit");
  await new Promise(setImmediate);
  await el("address-search-matches").children[0].children[1].fire("click");
  assert.deepEqual(JSON.parse(JSON.stringify(dispatched[0].detail)), {
    searchId: "opaque-search-1", matchId: "opaque-match-1", match: PUBLIC_MATCH,
  });
  assert.equal(calls.includes("release_address_search"), false);
  assert.equal(el("address-search-modal").hidden, true);
});

test("ordinary close cancels and releases a running search", async () => {
  const calls = [];
  let cancelled = false;
  const { el } = harness(async (command) => {
    calls.push(command);
    if (command === "start_address_search") return { id: "opaque-search-1" };
    if (command === "cancel_address_search") cancelled = true;
    if (command === "get_address_search") return snapshot({ status: cancelled ? "cancelled" : "running", checked: 10, matches: [] });
    return null;
  });
  fillValidForm(el);
  await el("address-search-form").fire("submit");
  await new Promise(setImmediate);
  await el("close-address-search").fire("click");
  await new Promise(setImmediate);
  assert.deepEqual(calls.slice(-3), ["cancel_address_search", "get_address_search", "release_address_search"]);
  assert.equal(el("address-search-modal").hidden, true);
});

test("invalid network prefix and overflowing ranges never start a search", async () => {
  let starts = 0;
  const { el } = harness(async (command) => { if (command === "start_address_search") starts++; });
  fillValidForm(el);
  el("address-search-target").value = "utest-public-fixture";
  await el("address-search-form").fire("submit");
  assert.equal(starts, 0);
  assert.match(el("address-search-form-status").textContent, /complete mainnet/);
  el("address-search-target").value = PUBLIC_MATCH.address;
  el("address-search-index-count").value = "10001";
  await el("address-search-form").fire("submit");
  assert.equal(starts, 0);
  assert.match(el("address-search-form-status").textContent, /1 to 10,000/);
});

test("a start response arriving after close is cancelled and released before restart", async () => {
  let finishStart;
  let cancelled = false;
  const calls = [];
  const { el } = harness(async (command) => {
    calls.push(command);
    if (command === "start_address_search") return new Promise((resolve) => { finishStart = resolve; });
    if (command === "cancel_address_search") cancelled = true;
    if (command === "get_address_search") return snapshot({ status: cancelled ? "cancelled" : "running" });
    return null;
  });
  fillValidForm(el);
  const pending = el("address-search-form").fire("submit");
  await new Promise(setImmediate);
  await el("close-address-search").fire("click");
  await el("open-address-search").fire("click");
  assert.equal(el("start-address-search").disabled, true);
  finishStart({ id: "opaque-search-1" });
  await pending;
  await new Promise(setImmediate);
  assert.deepEqual(calls.slice(-3), ["cancel_address_search", "get_address_search", "release_address_search"]);
  assert.equal(el("start-address-search").disabled, false);
  assert.equal(el("address-search-progress").hidden, true);
});

test("range ends, work cap, and ZecWallet Lite transparent scope reject without clearing seeds", async () => {
  let starts = 0;
  const { el } = harness(async (command) => { if (command === "start_address_search") starts++; });
  fillValidForm(el);
  const words = el("address-search-seeds").children[0].querySelector(".candidate-seed-words");
  const original = words.value;

  el("address-search-account-start").value = "2147483647";
  el("address-search-account-count").value = "2";
  await el("address-search-form").fire("submit");
  assert.match(el("address-search-form-status").textContent, /account range must end/);
  assert.equal(words.value, original);

  el("address-search-account-start").value = "0";
  el("address-search-account-count").value = "1";
  el("address-search-index-start").value = "2147483647";
  el("address-search-index-count").value = "2";
  await el("address-search-form").fire("submit");
  assert.match(el("address-search-form-status").textContent, /index range must end/);
  assert.equal(words.value, original);

  el("address-search-index-start").value = "0";
  el("address-search-account-count").value = "1000";
  el("address-search-index-count").value = "10000";
  await el("address-search-form").fire("submit");
  assert.match(el("address-search-form-status").textContent, /exceeds 10,000,000/);
  assert.equal(words.value, original);

  el("address-search-account-count").value = "2";
  el("address-search-index-count").value = "20";
  await el("address-search-form").fire("submit");
  assert.match(el("address-search-form-status").textContent, /account 0 only/);
  assert.equal(words.value, original);
  assert.equal(starts, 0);
});

test("two retained matches can recover sequentially without rerunning search and close releases", async () => {
  const second = { ...PUBLIC_MATCH, id: "opaque-match-2", seed_label: "Travel backup", seed_index: 1, path: "m/44'/133'/0'/0/9", index: 9 };
  const calls = [];
  const { el, dispatched, fireDocument } = harness(async (command) => {
    calls.push(command);
    if (command === "start_address_search") return { id: "opaque-search-1" };
    if (command === "get_address_search") return snapshot({ matches: [PUBLIC_MATCH, second] });
    return null;
  });
  fillValidForm(el);
  await el("address-search-form").fire("submit");
  await new Promise(setImmediate);
  const cards = el("address-search-matches").children;
  await cards[0].children[1].fire("click");
  assert.equal(el("address-search-modal").hidden, true);

  fireDocument("address-search-reopen", { searchId: "opaque-search-1" });
  await new Promise(setImmediate);
  assert.equal(el("address-search-modal").hidden, false);
  fireDocument("address-search-lock-recovery", { locked: true });
  const refreshedCards = el("address-search-matches").children;
  assert.equal(refreshedCards[1].children[1].disabled, true);
  fireDocument("address-search-lock-recovery", { locked: false });
  await refreshedCards[1].children[1].fire("click");

  const recoveries = dispatched.filter((event) => event.type === "address-match-recovery");
  assert.deepEqual(recoveries.map((event) => event.detail.matchId), ["opaque-match-1", "opaque-match-2"]);
  assert.equal(calls.filter((command) => command === "start_address_search").length, 1);

  fireDocument("address-search-reopen", { searchId: "opaque-search-1" });
  await new Promise(setImmediate);
  await el("close-address-search").fire("click");
  await new Promise(setImmediate);
  assert.deepEqual(calls.slice(-3), ["cancel_address_search", "get_address_search", "release_address_search"]);
});

test("reopening a live retained search refreshes, stays locked, resumes polling, and renders final results", async () => {
  const second = { ...PUBLIC_MATCH, id: "opaque-match-2", seed_label: "Later match", seed_index: 1 };
  let reads = 0;
  const { el, dispatched, fireDocument, runTimer } = harness(async (command) => {
    if (command === "start_address_search") return { id: "opaque-search-1" };
    if (command === "get_address_search") {
      reads++;
      if (reads === 1) return snapshot({ status: "running", checked: 10, matches: [PUBLIC_MATCH] });
      if (reads === 2) return snapshot({ status: "running", checked: 40, matches: [PUBLIC_MATCH, second] });
      return snapshot({ status: "complete", checked: 80, matches: [PUBLIC_MATCH, second] });
    }
    return null;
  });
  fillValidForm(el);
  await el("address-search-form").fire("submit");
  await new Promise(setImmediate);
  await el("address-search-live-matches").children[0].children[1].fire("click");
  fireDocument("address-search-lock-recovery", { locked: true });
  fireDocument("address-search-reopen", { searchId: "opaque-search-1" });
  await new Promise(setImmediate);
  assert.equal(el("address-search-progress").hidden, false);
  assert.equal(el("address-search-live-matches").children.length, 2);
  const laterButton = el("address-search-live-matches").children[1].children[1];
  assert.equal(laterButton.disabled, true);
  await laterButton.fire("click");
  assert.equal(dispatched.filter((event) => event.type === "address-match-recovery").length, 1);

  await runTimer();
  await new Promise(setImmediate);
  assert.equal(el("address-search-results").hidden, false);
  assert.equal(el("address-search-matches").children.length, 2);
  assert.equal(el("address-search-matches").children[0].children[1].disabled, true);
});

test("a failed backend release does not claim retained secrets were released", async () => {
  const { el, dispatched } = harness(async (command) => {
    if (command === "start_address_search") return { id: "opaque-search-1" };
    if (command === "get_address_search") return snapshot();
    if (command === "release_address_search") throw new Error("still retained");
    return null;
  });
  fillValidForm(el);
  await el("address-search-form").fire("submit");
  await new Promise(setImmediate);
  await el("address-search-again").fire("click");
  assert.equal(dispatched.some((event) => event.type === "address-search-released"), false);
  assert.equal(el("address-search-results").hidden, false);
  assert.match(el("address-search-limitation").textContent, /could not clear/);
});


test("ZecWallet Lite defaults to 1000 receive indices and unlocks accounts only for advanced coverage", async () => {
  const calls = [];
  const { el } = harness(async (command, args) => {
    calls.push([command, args]);
    if (command === "start_address_search") return { id: "opaque-search-1" };
    if (command === "get_address_search") return snapshot();
    return null;
  });
  await el("open-address-search").fire("click");
  assert.equal(el("address-search-index-count").value, "1000");
  assert.equal(el("address-search-change").checked, false);
  assert.equal(el("address-search-account-start").disabled, true);
  assert.equal(el("address-search-account-count").disabled, true);
  assert.equal(el("address-search-advanced").open, false);
  el("address-search-profile").value = "bip44";
  await el("address-search-profile").fire("change");
  assert.equal(el("address-search-account-start").disabled, false);
  el("address-search-account-start").value = "5";
  el("address-search-account-count").value = "10";
  el("address-search-profile").value = "zecwallet_lite";
  await el("address-search-profile").fire("change");
  assert.equal(el("address-search-account-start").value, "0");
  assert.equal(el("address-search-account-count").value, "1");
  el("address-search-target").value = PUBLIC_MATCH.address;
  el("address-search-network").value = "mainnet";
  el("address-search-seeds").children[0].querySelector(".candidate-seed-words").value = "synthetic fixture";
  await el("address-search-form").fire("submit");
  const input = calls.find(([cmd]) => cmd === "start_address_search")[1].input;
  assert.deepEqual([input.account_start, input.account_count, input.index_start, input.index_count, input.include_change], [0, 1, 0, 1000, false]);
});

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
  ];
  const elements = new Map(ids.map((id) => [id, new Element()]));
  elements.get("address-search-form").tagName = "FORM";
  const dispatched = [];
  const document = {
    getElementById: (id) => elements.get(id),
    createElement: (tag) => new Element(tag),
    addEventListener: (type, fn) => { if (type === "DOMContentLoaded") fn(); },
    dispatchEvent: (event) => dispatched.push(event),
  };
  class CustomEvent { constructor(type, options) { this.type = type; this.detail = options.detail; } }
  const window = { __TAURI__: { core: { invoke } }, addEventListener() {}, setTimeout: () => 1, clearTimeout() {} };
  vm.runInNewContext(fs.readFileSync("gui/src/address-search.js", "utf8"), { document, window, CustomEvent, console });
  return { el: (id) => elements.get(id), dispatched };
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

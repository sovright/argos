const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function declaration(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return source.slice(start, end + 3);
}

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.className = "";
    this.textContent = "";
    this.title = "";
    this.listeners = {};
    this.classList = {
      add: (...names) => {
        this.className = [this.className, ...names].filter(Boolean).join(" ");
      },
    };
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  addEventListener(name, listener) {
    this.listeners[name] = listener;
  }
}

function descendants(element) {
  return [element, ...element.children.flatMap(descendants)];
}

function loadBuildSessionRow() {
  const document = { createElement: (tagName) => new FakeElement(tagName) };
  return vm.runInNewContext(
    `${declaration("fmtRelativeTime")}\n${declaration("buildSessionRow")}; buildSessionRow`,
    {
      document,
      openResumeModal() {},
      dismissSession() {},
    },
  );
}

test("legacy untrusted rows explain preservation and rescan without resume or metrics", () => {
  const buildSessionRow = loadBuildSessionRow();
  const row = buildSessionRow(
    {
      workspace_path: "/data/mainnet/workspace-deadbeef/birthday-3280000/auto-gap-20",
      label: "must not be rendered",
      network: "mainnet",
      birthday: 3280000,
      synced_to_height: 3200000,
      target_height: 3300000,
      last_run_at_epoch_seconds: 42,
      match_coordinates: null,
      transparent_scan: null,
      requires_rescan: true,
      legacy_untrusted: true,
    },
    () => {},
  );

  const nodes = descendants(row);
  const text = nodes.map((node) => node.textContent).filter(Boolean).join(" ");
  const buttons = nodes.filter((node) => node.tagName === "button");

  assert.match(text, /workspace is preserved/i);
  assert.match(text, /predates.*private-storage lineage/i);
  assert.match(text, /cannot be safely resumed/i);
  assert.match(text, /choose a new empty.*data directory/i);
  assert.match(text, /workspace-v2/);
  assert.match(text, /rescan/i);
  assert.doesNotMatch(text, /must not be rendered/);
  assert.doesNotMatch(text, /3,200,000|3,300,000|3,280,000/);
  assert.equal(buttons.some((button) => button.textContent === "Resume"), false);
  assert.equal(buttons.some((button) => /Dismiss/.test(button.textContent)), true);
});

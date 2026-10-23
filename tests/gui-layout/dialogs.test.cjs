const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { chromium, webkit } = require("../../gui/node_modules/playwright");

// Run with: cd gui && npm ci && npx playwright install chromium && npm run test:layout
// Set LAYOUT_BROWSER=webkit to exercise the engine used by macOS Tauri.
const root = path.resolve(__dirname, "../..");
let browser;
before(async () => {
  browser = await (process.env.LAYOUT_BROWSER === "webkit" ? webkit : chromium).launch();
});
after(async () => { await browser?.close(); });

async function pageAt(viewport) {
  const page = await browser.newPage({ viewport });
  await page.route("http://argos-layout.test/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    // The layout does not need Tauri or wallet state. Keep the real address
    // matcher script so its candidate rows are the ones users actually see.
    if (pathname === "/main.js") return route.fulfill({ body: "", contentType: "text/javascript" });
    const file = path.join(root, "gui/src", pathname === "/" ? "index.html" : pathname);
    const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".svg": "image/svg+xml" };
    await route.fulfill({ body: await fs.readFile(file), contentType: types[path.extname(file)] });
  });
  await page.goto("http://argos-layout.test/");
  await page.evaluate(() => document.fonts.ready);
  await page.evaluate(() => {
    document.querySelectorAll(".guide-overlay").forEach((el) => { el.style.display = "none"; });
  });
  return page;
}

async function assertInside(page, selector) {
  const box = await page.locator(selector).boundingBox();
  const { width, height } = page.viewportSize();
  assert.ok(box && box.x >= -1 && box.y >= -1 && box.x + box.width <= width + 1 && box.y + box.height <= height + 1,
    `${selector} must fit inside ${width}x${height}: ${JSON.stringify(box)}`);
}

// Removing the shared dialog height constraint makes the resume card extend
// above and below the viewport; removing responsive candidate sizing clips
// the address matcher's Remove control at the minimum desktop width.
for (const viewport of [{ width: 1320, height: 880 }, { width: 780, height: 640 }, { width: 780, height: 480 }, { width: 624, height: 512 }]) {
  for (const [overlay, panel, controls, source] of [
    ["#resume-modal", ".modal-card", ["#resume-bip39-passphrase", "#resume-cancel", "#resume-confirm"], "seed"],
    ["#resume-modal", ".modal-card", ["#resume-wallet-pick", "#resume-sapling-keys", "#resume-cancel", "#resume-confirm"], "wallet"],
    ["#address-search-modal", ".address-search-card", ["#close-address-search", ".remove-candidate-seed", "#start-address-search"]],
    ["#guide-overlay", ".guide-panel", ["#close-guide"]],
    ["#donate-overlay", ".guide-panel", ["#close-donate"]],
    ["#tos-overlay", ".tos-panel", ["#tos-reject", "#tos-accept"]],
  ]) {
    test(`${overlay}${source ? ` (${source})` : ""} controls stay reachable at ${viewport.width}x${viewport.height}`, async () => {
      const page = await pageAt(viewport);
      try {
        if (overlay === "#address-search-modal") {
          await page.locator("#open-address-search").evaluate((el) => el.click());
          await page.locator("#address-search-advanced").evaluate((el) => { el.open = true; });
        } else {
          await page.locator(overlay).evaluate((el) => { el.hidden = false; el.style.display = "flex"; });
        }
        if (source) {
          await page.evaluate((mode) => {
            document.querySelector("#resume-source").value = mode;
            document.querySelector("#resume-seed-fields").hidden = mode !== "seed";
            document.querySelector("#resume-wallet-fields").hidden = mode !== "wallet";
            document.querySelector("#resume-sapling-field").hidden = mode !== "wallet";
            document.querySelector("#resume-bip39-passphrase-field").hidden = mode !== "seed";
          }, source);
          assert.equal(await page.locator("#resume-bip39-passphrase-field").isVisible(), source === "seed", "BIP39 field visibility follows the recovery source");
          assert.equal(await page.locator("#resume-wallet-fields").isVisible(), source === "wallet", "wallet field visibility follows the recovery source");
          assert.equal(await page.locator("#resume-sapling-field").isVisible(), source === "wallet", "additional key visibility follows the recovery source");
        }
        if (overlay === "#tos-overlay") {
          await page.locator("#tos-text").evaluate((el, text) => { el.textContent = text; },
            await fs.readFile(path.join(root, "crates/zeck-core/assets/terms-of-service.md"), "utf8"));
        }
        await page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished)));
        await assertInside(page, `${overlay} ${panel}`);
        const horizontal = await page.locator(`${overlay} ${panel}`).evaluate((el) => ({ client: el.clientWidth, scroll: el.scrollWidth }));
        assert.ok(horizontal.scroll <= horizontal.client + 1, `${overlay} content must not clip horizontally: ${JSON.stringify(horizontal)}`);
        for (const control of controls) {
          await page.locator(control).scrollIntoViewIfNeeded();
          await assertInside(page, control);
          const reachable = await page.locator(control).evaluate((el) => {
            const box = el.getBoundingClientRect();
            const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
            return hit === el || el.contains(hit);
          });
          assert.ok(reachable, `${control} must be reachable by pointer after scrolling`);
        }
      } finally { await page.close(); }
    });
  }
}

for (const viewport of [{ width: 780, height: 640 }, { width: 1024, height: 600 }]) {
  test(`wizard screens do not clip their content at ${viewport.width}x${viewport.height}`, async () => {
    const page = await pageAt(viewport);
    try {
      const screens = await page.locator(".screen").evaluateAll((els) => els.map((el) => el.dataset.step));
      for (const step of screens) {
        await page.locator(".screen").evaluateAll((els, selected) => els.forEach((el) => el.classList.toggle("active", el.dataset.step === selected)), step);
        const widths = await page.locator(`.screen[data-step="${step}"]`).evaluate((el) => ({ client: el.clientWidth, scroll: el.scrollWidth }));
        assert.ok(widths.scroll <= widths.client + 1, `${step} screen content clips horizontally: ${JSON.stringify(widths)}`);
      }
    } finally { await page.close(); }
  });
}

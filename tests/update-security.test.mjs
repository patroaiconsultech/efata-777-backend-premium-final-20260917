import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const banner = fs.readFileSync(
  "src/components/PwaUpdateBanner.tsx",
  "utf8",
);
const controller = fs.readFileSync(
  "src/pwa/updateController.ts",
  "utf8",
);
const registration = fs.readFileSync(
  "src/pwa/registerServiceWorker.ts",
  "utf8",
);
const sw = fs.readFileSync("public/sw.js", "utf8");

test("update targets registration.waiting", () => {
  assert.match(controller, /registration\.waiting !== detail\.waiting/);
  assert.match(controller, /detail\.waiting\.postMessage/);
});

test("controllerchange listener is installed before SKIP_WAITING", () => {
  const listener = controller.indexOf('addEventListener("controllerchange"');
  const message = controller.indexOf('postMessage({ type: "SKIP_WAITING" })');
  assert.ok(listener >= 0);
  assert.ok(message > listener);
});

test("timeout fails without page reload", () => {
  assert.match(controller, /activation timed out/);
  assert.doesNotMatch(controller, /location\.reload/);
});

test("banner reloads only after activation promise resolves", () => {
  const awaitIndex = banner.indexOf("await activateWaitingWorker");
  const reloadIndex = banner.indexOf("window.location.reload()");
  assert.ok(awaitIndex >= 0);
  assert.ok(reloadIndex > awaitIndex);
});

test("banner prevents duplicate reload", () => {
  assert.match(banner, /reloadIssuedRef/);
  assert.match(banner, /if \(!reloadIssuedRef\.current\)/);
});

test("controlled update states are explicit", () => {
  for (const state of [
    "IDLE",
    "UPDATE_AVAILABLE",
    "ACTIVATING",
    "ACTIVATED",
    "FAILED",
  ]) {
    assert.match(controller, new RegExp(state));
  }
});

test("registration dispatches the actual waiting worker", () => {
  assert.match(registration, /registration\.waiting/);
  assert.match(registration, /dispatchWaitingUpdate/);
});

test("cache model is explicit allowlist", () => {
  assert.match(sw, /EXACT_PUBLIC_PATHS/);
  assert.match(sw, /PUBLIC_PREFIXES/);
  assert.match(sw, /isPublicAllowlistedPath/);
});

test("protected paths are rejected before allowlist", () => {
  const protectedIndex = sw.indexOf("isProtectedPath(url.pathname)");
  const allowlistIndex = sw.indexOf("isPublicAllowlistedPath(url.pathname)");
  assert.ok(protectedIndex >= 0);
  assert.ok(allowlistIndex > protectedIndex);
});

test("authorization requests are not intercepted", () => {
  assert.match(sw, /request\.headers\.has\("authorization"\)/);
});

test("private and no-store responses are not cached", () => {
  assert.match(sw, /cacheControl\.includes\("no-store"\)/);
  assert.match(sw, /cacheControl\.includes\("private"\)/);
});

test("vary authorization and cookie responses are not cached", () => {
  assert.match(sw, /normalized === "authorization"/);
  assert.match(sw, /normalized === "cookie"/);
});

test("old ORKIO caches are removed", () => {
  assert.match(sw, /CACHE_PREFIXES/);
  assert.match(sw, /"orkio-v2-"/);
  assert.match(sw, /caches\.delete/);
});

test("non-GET and cross-origin requests are not intercepted", () => {
  assert.match(sw, /request\.method !== "GET"/);
  assert.match(sw, /url\.origin !== self\.location\.origin/);
});

test("service worker uses public offline fallback", () => {
  assert.match(sw, /caches\.match\("\/offline\.html"\)/);
  assert.doesNotMatch(
    fs.readFileSync("public/offline.html", "utf8"),
    /token|tenant_id|private message/i,
  );
});

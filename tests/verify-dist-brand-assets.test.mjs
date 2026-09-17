import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("dist verification requires current PatroAI PWA icons", () => {
  const source = fs.readFileSync("scripts/verify-dist.mjs", "utf8");
  assert.match(source, /icons\/patroai-192\.png/);
  assert.match(source, /icons\/patroai-maskable-192\.png/);
  assert.match(source, /icons\/patroai-512\.png/);
  assert.match(source, /icons\/patroai-maskable-512\.png/);
  assert.doesNotMatch(source, /icons\/orkio-/);
});

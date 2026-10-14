import assert from "node:assert/strict";
import test from "node:test";
import worker from "./worker.mjs";

const token = "test-only-download-key";
const payload = "rules: []\n";

function environment(secret = token) {
  const calls = [];
  return {
    calls,
    DOWNLOAD_TOKEN: secret,
    CONFIG_BUCKET: {
      async get(key) {
        calls.push(key);
        return { body: payload };
      },
    },
  };
}

test("missing, wrong, and duplicate keys never read the private bucket", async () => {
  for (const query of ["", "?key=wrong", `?key=${token}&key=${token}`]) {
    const env = environment();
    const response = await worker.fetch(new Request(`https://test.invalid/egern.yaml${query}`), env);
    assert.equal(response.status, 403);
    assert.deepEqual(env.calls, []);
    assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0");
  }
});

test("an unconfigured or empty secret fails closed", async () => {
  for (const secret of [null, ""]) {
    const env = environment(secret);
    const response = await worker.fetch(new Request("https://test.invalid/egern.yaml?key="), env);
    assert.equal(response.status, 403);
    assert.deepEqual(env.calls, []);
  }
});

test("authorized GET returns raw YAML with caching disabled", async () => {
  const env = environment();
  const response = await worker.fetch(new Request(`https://test.invalid/egern.yaml?key=${token}`), env);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), payload);
  assert.deepEqual(env.calls, ["egern.yaml"]);
  assert.equal(response.headers.get("Content-Type"), "application/yaml; charset=utf-8");
  assert.equal(response.headers.get("Cache-Control"), "private, no-store, max-age=0");
});

test("authorized HEAD returns no body", async () => {
  const response = await worker.fetch(
    new Request(`https://test.invalid/egern.yaml?key=${token}`, { method: "HEAD" }), environment(),
  );
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "");
});

test("unknown paths and upload methods never access the bucket", async () => {
  for (const [path, method, status] of [["/other", "GET", 404], ["/egern.yaml", "PUT", 405]]) {
    const env = environment();
    const response = await worker.fetch(new Request(`https://test.invalid${path}?key=${token}`, { method }), env);
    assert.equal(response.status, status);
    assert.deepEqual(env.calls, []);
  }
});

test("missing objects and storage failures do not reveal private error details", async () => {
  const env = environment();
  env.CONFIG_BUCKET.get = async () => null;
  assert.equal((await worker.fetch(new Request(`https://test.invalid/egern.yaml?key=${token}`), env)).status, 404);
  env.CONFIG_BUCKET.get = async () => { throw new Error("private storage details"); };
  const response = await worker.fetch(new Request(`https://test.invalid/egern.yaml?key=${token}`), env);
  assert.equal(response.status, 503);
  assert.equal(await response.text(), "Temporarily unavailable");
});

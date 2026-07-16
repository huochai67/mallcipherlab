#!/usr/bin/env node
/**
 * Node differential oracle for the pinned official CDN snapshot.
 *
 * The production-facing Python entry is h5st_runtime.py. This small wrapper loads
 * the exact same source and browser shim so tests can compare QuickJS and V8.
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const SOURCE = path.join(
  ROOT,
  "archives",
  "js_security_v3_0.1.4_20260527205706.js",
);
const SHIM = path.join(__dirname, "browser_shim.js");

function loadVm(options = {}) {
  global.__JD_VM_CONFIG__ = {
    ...(Number.isFinite(options.now_ms) ? { now_ms: options.now_ms } : {}),
    ...(Number.isFinite(options.seed) ? { seed: options.seed } : {}),
    ...(options.user_agent ? { user_agent: options.user_agent } : {}),
  };
  vm.runInThisContext(fs.readFileSync(SHIM, "utf8"), { filename: SHIM });
  vm.runInThisContext(fs.readFileSync(SOURCE, "utf8"), { filename: SOURCE });
  if (typeof global.ParamsSign !== "function") {
    throw new Error("pinned VM did not expose ParamsSign");
  }
}

function generateH5st(appId, params, options = {}) {
  loadVm(options);
  const signer = new global.ParamsSign({
    appId,
    beta: false,
    onSign() {},
    onRequestToken() {},
    onRequestTokenRemotely() {},
  });
  if (options.fingerprint || options.token) {
    const originalRds = signer._$rds;
    signer._$rds = function requestDepsFixture() {
      originalRds.call(this);
      if (options.fingerprint) this._fingerprint = options.fingerprint;
      if (options.token) {
        this._token = options.token;
        this._isNormal = true;
      }
    };
  }
  const result = signer.signSync(params);
  if (!result.h5st || result.h5st.split(";").length !== 10) {
    throw new Error("VM returned an invalid 10-part h5st result");
  }
  return result;
}

function execute(input) {
  const appId = input.app_id || input.appId || input.appid;
  const params = input.params;
  if (!appId || !params || typeof params !== "object") {
    throw new Error("input requires app_id and params");
  }
  return generateH5st(appId, params, input);
}

function main() {
  const args = process.argv.slice(2);
  if (args[0] === "--stdin") {
    let body = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { body += chunk; });
    process.stdin.on("end", () => {
      try {
        process.stdout.write(JSON.stringify(execute(JSON.parse(body))));
      } catch (error) {
        process.stderr.write(`${JSON.stringify({ error: error.message })}\n`);
        process.exitCode = 1;
      }
    });
    return;
  }

  if (args.length < 2) {
    process.stderr.write(
      "Usage: node h5st_generator.js APP_ID JSON_PARAMS [NOW_MS] [SEED]\n",
    );
    process.exitCode = 2;
    return;
  }
  try {
    const result = generateH5st(args[0], JSON.parse(args[1]), {
      now_ms: args[2] === undefined ? undefined : Number(args[2]),
      seed: args[3] === undefined ? undefined : Number(args[3]),
    });
    process.stdout.write(JSON.stringify(result));
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ error: error.message })}\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { generateH5st };

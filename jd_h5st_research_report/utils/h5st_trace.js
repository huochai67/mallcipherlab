#!/usr/bin/env node
/**
 * Intermediate-state tracer for the pinned h5st 5.3 VM.
 *
 * Loads browser_shim + official snapshot, instruments ParamsSign methods and
 * defaultAlgorithm hooks, then emits a structured JSON trace that pure-Python
 * ports can use as ground truth while detaching from vendor JS.
 *
 * Usage:
 *   node utils/h5st_trace.js APP_ID JSON_PARAMS [NOW_MS] [SEED]
 *   node utils/h5st_trace.js --stdin < input.json
 *   node utils/h5st_trace.js --golden
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const SOURCE = path.join(
  ROOT,
  "archives",
  "js_security_v3_0.1.4_20260527205706.js",
);
const SHIM = path.join(__dirname, "browser_shim.js");
const GOLDEN = path.join(ROOT, "tests", "fixtures", "golden_h5st.json");

const METHOD_NAMES = [
  "_$cps",
  "_$rds",
  "_$clt",
  "_$ms",
  "_$sdnmd",
  "_$pam",
  "_$gsp",
  "_$gs",
  "_$gsd",
  "_$icg",
  "_$gdk",
  "_$atm",
  "_$ram",
];

function summarize(value, depth = 0) {
  if (value === null || value === undefined) return value;
  const type = typeof value;
  if (type === "string") {
    if (value.length <= 240) return value;
    return {
      type: "string",
      length: value.length,
      sha256: crypto.createHash("sha256").update(value).digest("hex"),
      head: value.slice(0, 96),
      tail: value.slice(-48),
    };
  }
  if (type === "number" || type === "boolean") return value;
  if (type === "function") return { type: "function", name: value.name || "" };
  if (Array.isArray(value)) {
    if (depth > 2) return { type: "array", length: value.length };
    return value.map((item) => summarize(item, depth + 1));
  }
  if (type === "object") {
    if (value.words && typeof value.sigBytes === "number") {
      const bytes = [];
      for (let i = 0; i < value.sigBytes; i += 1) {
        bytes.push((value.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
      }
      return {
        type: "WordArray",
        sigBytes: value.sigBytes,
        hex: Buffer.from(bytes).toString("hex"),
      };
    }
    if (depth > 2) return { type: "object", keys: Object.keys(value).slice(0, 24) };
    const out = {};
    for (const key of Object.keys(value).slice(0, 40)) {
      try {
        out[key] = summarize(value[key], depth + 1);
      } catch (error) {
        out[key] = { error: String(error.message || error) };
      }
    }
    return out;
  }
  return String(value);
}

function snapshotSigner(signer) {
  return {
    appId: signer._appId,
    version: signer._version,
    fingerprint: signer._fingerprint,
    token: signer._token,
    defaultToken: signer._defaultToken,
    isNormal: signer._isNormal,
    genKey: summarize(signer.__genKey),
    defaultAlgorithmKeys: Object.keys(signer._defaultAlgorithm || {}),
    algoKeys: Object.keys(signer._algos || {}),
  };
}

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

function instrumentSigner(signer, calls) {
  for (const name of Object.keys(signer._defaultAlgorithm || {})) {
    const original = signer._defaultAlgorithm[name];
    signer._defaultAlgorithm[name] = function wrappedAlgo(...args) {
      const result = original.apply(this, args);
      calls.push({
        kind: "defaultAlgorithm",
        name,
        args: args.map((item) => summarize(item)),
        result: summarize(result),
      });
      return result;
    };
  }

  for (const name of Object.keys(signer._algos || {})) {
    const original = signer._algos[name];
    signer._algos[name] = function wrappedHash(...args) {
      const result = original.apply(this, args);
      calls.push({
        kind: "algo",
        name,
        args: args.map((item) => summarize(item)),
        result: summarize(result),
      });
      return result;
    };
  }

  for (const name of METHOD_NAMES) {
    if (typeof signer[name] !== "function") continue;
    const original = signer[name].bind(signer);
    signer[name] = function wrappedMethod(...args) {
      const before = snapshotSigner(signer);
      const result = original(...args);
      const after = snapshotSigner(signer);
      calls.push({
        kind: "method",
        name,
        args: args.map((item) => summarize(item)),
        result: summarize(result),
        before,
        after,
      });
      return result;
    };
  }
}

function splitH5st(h5st) {
  const parts = String(h5st).split(";");
  return {
    count: parts.length,
    lengths: parts.map((part) => part.length),
    parts: parts.map((part, index) => ({
      index: index + 1,
      length: part.length,
      value: part,
      sha256: crypto.createHash("sha256").update(part).digest("hex"),
    })),
  };
}

function traceH5st(appId, params, options = {}) {
  loadVm(options);
  const calls = [];
  const signer = new global.ParamsSign({
    appId,
    beta: Boolean(options.debug),
    onSign() {},
    onRequestToken() {},
    onRequestTokenRemotely() {},
  });

  if (options.fingerprint || options.token) {
    const originalRds = signer._$rds.bind(signer);
    signer._$rds = function requestDepsFixture() {
      originalRds();
      if (options.fingerprint) signer._fingerprint = options.fingerprint;
      if (options.token) {
        signer._token = options.token;
        signer._isNormal = true;
      }
    };
  }

  instrumentSigner(signer, calls);
  const started = Date.now();
  const result = signer.signSync(params);
  const elapsedMs = Date.now() - started;

  if (!result || typeof result.h5st !== "string" || result.h5st.split(";").length !== 10) {
    throw new Error("VM returned an invalid 10-part h5st result");
  }

  const h5stParts = splitH5st(result.h5st);
  const methodOrder = calls.filter((call) => call.kind === "method").map((call) => call.name);

  return {
    schema: 1,
    description: "Pinned h5st 5.3 intermediate trace for pure-Python reconstruction",
    source: path.basename(SOURCE),
    input: {
      app_id: appId,
      params,
      options: {
        now_ms: options.now_ms,
        seed: options.seed,
        fingerprint: options.fingerprint,
        token: options.token,
      },
    },
    result,
    h5st: h5stParts,
    final_signer_state: snapshotSigner(signer),
    method_order: methodOrder,
    call_count: calls.length,
    elapsed_ms: elapsedMs,
    calls,
    recovered_pipeline: {
      note: "Derived from method hooks on the pinned build; crypto host is still build-specific.",
      steps: [
        "_$cps(params) -> sorted [{key,value}, ...] used as sign body",
        "_$rds() -> fingerprint (+ token/algo when storage hit)",
        "_$clt(now_ms) -> part8 env/extension payload",
        "_$gdk(token, fp, timeExpr, appId) via double _$atm(local_key_3, ...)",
        "_$gs(key, sortedParams) -> part5",
        "_$gsd(key, sortedParams) -> part9",
        "_$gsp(...) joins ten parts; part10 produced inside _$ms before join",
      ],
      crypto: {
        seData_segments: 6,
        seData_multiplier: 28,
        seData_alphabet:
          "nmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvutsrqpo",
        eData_salt: "RvI<7|",
        local_key_3: "HmacSHA256(message, key) with modified seData/_eData path",
      },
    },
  };
}

function execute(input) {
  const appId = input.app_id || input.appId || input.appid;
  const params = input.params;
  if (!appId || !params || typeof params !== "object") {
    throw new Error("input requires app_id and params");
  }
  return traceH5st(appId, params, input);
}

function main() {
  const args = process.argv.slice(2);
  if (args[0] === "--golden") {
    const fixture = JSON.parse(fs.readFileSync(GOLDEN, "utf8"));
    const trace = traceH5st(fixture.app_id, fixture.params, fixture.options || {});
    process.stdout.write(`${JSON.stringify(trace, null, 2)}\n`);
    return;
  }

  if (args[0] === "--stdin") {
    let body = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      body += chunk;
    });
    process.stdin.on("end", () => {
      try {
        process.stdout.write(`${JSON.stringify(execute(JSON.parse(body)), null, 2)}\n`);
      } catch (error) {
        process.stderr.write(`${JSON.stringify({ error: error.message })}\n`);
        process.exitCode = 1;
      }
    });
    return;
  }

  if (args.length < 2) {
    process.stderr.write(
      "Usage: node h5st_trace.js APP_ID JSON_PARAMS [NOW_MS] [SEED]\n" +
        "       node h5st_trace.js --golden\n" +
        "       node h5st_trace.js --stdin < input.json\n",
    );
    process.exitCode = 2;
    return;
  }

  try {
    const trace = traceH5st(args[0], JSON.parse(args[1]), {
      now_ms: args[2] === undefined ? undefined : Number(args[2]),
      seed: args[3] === undefined ? undefined : Number(args[3]),
    });
    process.stdout.write(`${JSON.stringify(trace, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ error: error.message })}\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { traceH5st };

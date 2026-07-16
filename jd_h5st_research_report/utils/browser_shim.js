(function (root) {
  "use strict";

  var config = root.__JD_VM_CONFIG__ || {};
  function setGlobal(name, value) {
    try {
      root[name] = value;
    } catch (error) {
      Object.defineProperty(root, name, {
        configurable: true,
        enumerable: true,
        writable: true,
        value: value
      });
    }
  }

  // A deterministic clock and an explicit UTC+8 view make fixtures independent
  // of the host operating-system timezone.
  var NativeDate = root.Date;
  if (typeof config.now_ms === "number") {
    var fixedNow = Math.trunc(config.now_ms);
    function FixedDate() {
      var args = Array.prototype.slice.call(arguments);
      if (!(this instanceof FixedDate)) {
        return new NativeDate(fixedNow).toString();
      }
      if (args.length === 0) return new NativeDate(fixedNow);
      return new (Function.prototype.bind.apply(NativeDate, [null].concat(args)))();
    }
    FixedDate.prototype = NativeDate.prototype;
    FixedDate.now = function () { return fixedNow; };
    FixedDate.parse = NativeDate.parse;
    FixedDate.UTC = NativeDate.UTC;
    root.Date = FixedDate;
  }
  var timezoneMinutes = typeof config.timezone_offset_minutes === "number"
    ? Math.trunc(config.timezone_offset_minutes)
    : 480;
  var nativeGetTime = NativeDate.prototype.getTime;
  function shiftedDate(value) {
    return new NativeDate(nativeGetTime.call(value) + timezoneMinutes * 60000);
  }
  NativeDate.prototype.getFullYear = function () { return shiftedDate(this).getUTCFullYear(); };
  NativeDate.prototype.getMonth = function () { return shiftedDate(this).getUTCMonth(); };
  NativeDate.prototype.getDate = function () { return shiftedDate(this).getUTCDate(); };
  NativeDate.prototype.getDay = function () { return shiftedDate(this).getUTCDay(); };
  NativeDate.prototype.getHours = function () { return shiftedDate(this).getUTCHours(); };
  NativeDate.prototype.getMinutes = function () { return shiftedDate(this).getUTCMinutes(); };
  NativeDate.prototype.getSeconds = function () { return shiftedDate(this).getUTCSeconds(); };
  NativeDate.prototype.getMilliseconds = function () { return shiftedDate(this).getUTCMilliseconds(); };
  NativeDate.prototype.getTimezoneOffset = function () { return -timezoneMinutes; };

  if (typeof config.seed === "number") {
    var randomState = config.seed >>> 0;
    Math.random = function () {
      randomState = (randomState + 0x6d2b79f5) >>> 0;
      var value = randomState;
      value = Math.imul(value ^ (value >>> 15), value | 1);
      value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
      return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
    };
  }

  root.window = root;
  root.self = root;
  setGlobal("navigator", {
    userAgent: config.user_agent ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    language: "zh-CN",
    languages: ["zh-CN", "zh"],
    platform: "Win32",
    hardwareConcurrency: 8,
    deviceMemory: 8,
    vendor: "Google Inc.",
    cookieEnabled: true,
    plugins: { length: 0 },
    mimeTypes: { length: 0 },
    webdriver: false
  });
  root.location = {
    href: "https://search.jd.com/Search",
    origin: "https://search.jd.com",
    host: "search.jd.com",
    hostname: "search.jd.com",
    protocol: "https:",
    pathname: "/Search",
    search: "",
    hash: ""
  };
  root.screen = {
    width: 1920,
    height: 1080,
    availWidth: 1920,
    availHeight: 1040,
    colorDepth: 24,
    pixelDepth: 24
  };
  root.history = { length: 1 };

  function element() {
    return {
      style: {},
      children: [],
      childNodes: [],
      innerHTML: "",
      textContent: "",
      src: "",
      type: "",
      appendChild: function () {},
      removeChild: function () {},
      setAttribute: function () {},
      getAttribute: function () { return null; },
      getContext: function () { return null; },
      toDataURL: function () { return ""; },
      parentNode: { removeChild: function () {} }
    };
  }

  root.document = {
    cookie: "",
    referrer: "",
    createElement: element,
    getElementsByTagName: function () { return []; },
    querySelector: function () { return null; },
    body: element(),
    head: element(),
    documentElement: element(),
    currentScript: null,
    addEventListener: function () {},
    removeEventListener: function () {}
  };

  function memoryStorage() {
    var values = Object.create(null);
    return {
      getItem: function (key) {
        return Object.prototype.hasOwnProperty.call(values, key) ? values[key] : null;
      },
      setItem: function (key, value) { values[key] = String(value); },
      removeItem: function (key) { delete values[key]; },
      clear: function () { values = Object.create(null); }
    };
  }
  root.localStorage = memoryStorage();
  root.sessionStorage = memoryStorage();

  function Element() {}
  Element.prototype.scrollIntoViewIfNeeded = function () {};
  root.Element = Element;
  root.HTMLAllCollection = function HTMLAllCollection() {};
  root.Window = function Window() {};
  root.Document = function Document() {};
  root.HTMLDocument = function HTMLDocument() {};
  root.addEventListener = function () {};
  root.removeEventListener = function () {};
  root.getComputedStyle = function () { return {}; };

  // Timers intentionally never execute callbacks: the synchronous local-token
  // path is exercised and the delayed remote-algorithm request stays dormant.
  root.setTimeout = function () { return 0; };
  root.clearTimeout = function () {};
  root.setInterval = function () { return 0; };
  root.clearInterval = function () {};

  var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  root.atob = function (input) {
    var value = String(input).replace(/[^A-Za-z0-9+/=]/g, "");
    var output = "";
    var index = 0;
    while (index < value.length) {
      var e1 = base64Chars.indexOf(value.charAt(index++));
      var e2 = base64Chars.indexOf(value.charAt(index++));
      var e3 = base64Chars.indexOf(value.charAt(index++));
      var e4 = base64Chars.indexOf(value.charAt(index++));
      output += String.fromCharCode((e1 << 2) | (e2 >> 4));
      if (e3 !== 64) output += String.fromCharCode(((e2 & 15) << 4) | (e3 >> 2));
      if (e4 !== 64) output += String.fromCharCode(((e3 & 3) << 6) | e4);
    }
    return output;
  };
  root.btoa = function (input) {
    var value = String(input);
    var output = "";
    for (var block = 0, charCode, index = 0, map = base64Chars;
      value.charAt(index | 0) || ((map = "="), index % 1);
      output += map.charAt(63 & (block >> (8 - (index % 1) * 8)))) {
      charCode = value.charCodeAt(index += 3 / 4);
      if (charCode > 255) throw new Error("base64 input is outside the byte range");
      block = (block << 8) | charCode;
    }
    return output;
  };

  // QuickJS omits the legacy RegExp.$1 static used by the sampled date
  // formatter.  Preserve that small piece of browser-compatible behaviour.
  var originalExec = RegExp.prototype.exec;
  RegExp["$1"] = "";
  RegExp.prototype.test = function (value) {
    var match = originalExec.call(this, value);
    RegExp["$1"] = match && match.length > 1 ? match[1] : "";
    return !!match;
  };

  setGlobal("crypto", {
    getRandomValues: function (array) {
      for (var i = 0; i < array.length; i += 1) {
        array[i] = Math.floor(Math.random() * 256);
      }
      return array;
    }
  });

  root.XMLHttpRequest = function XMLHttpRequest() {
    this.readyState = 0;
    this.status = 0;
    this.responseText = "";
  };
  root.XMLHttpRequest.prototype.open = function () {};
  root.XMLHttpRequest.prototype.setRequestHeader = function () {};
  root.XMLHttpRequest.prototype.send = function () {};

  if (typeof root.console === "undefined") {
    root.console = { log: function () {}, error: function () {}, warn: function () {} };
  }
})(globalThis);

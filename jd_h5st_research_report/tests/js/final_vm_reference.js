#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const fixturePath = process.argv[2] || path.join(__dirname, '..', 'fixtures', 'final_vm.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

// Minimal deterministic host matching utils/h5st_generator.js.  The exact
// source build is loaded below; only the four worker methods are replaced so
// this fixture isolates and differentially tests dispatcher entry 5134.
Object.defineProperty(global, 'navigator', { configurable: true, writable: true, value: {
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
  language: 'zh-CN',
  languages: ['zh-CN', 'zh'],
  platform: 'Win32',
  hardwareConcurrency: 8,
  deviceMemory: 8,
  vendor: 'Google Inc.',
  cookieEnabled: true,
  plugins: { length: 5 },
  mimeTypes: { length: 4 },
  webdriver: false,
} });
global.window = global;
global.self = global;
global.location = {
  href: 'https://search.jd.com/Search',
  origin: 'https://search.jd.com',
  host: 'search.jd.com',
  hostname: 'search.jd.com',
  protocol: 'https:',
};
global.document = {
  cookie: '',
  referrer: '',
  createElement: () => ({}),
  getElementsByTagName: () => [],
  body: { innerHTML: '' },
  head: null,
  currentScript: null,
};
global.atob = (value) => Buffer.from(value, 'base64').toString('binary');
global.btoa = (value) => Buffer.from(value, 'binary').toString('base64');
global.Element = function Element() {};
global.HTMLAllCollection = function HTMLAllCollection() {};

const RealDate = Date;
class FixedDate extends RealDate {
  constructor(...args) {
    super(...(args.length ? args : [fixture.fixed_now]));
  }
  static now() {
    return fixture.fixed_now;
  }
}
global.Date = FixedDate;
Math.random = () => 0.125;
Object.defineProperty(global, 'crypto', {
  configurable: true,
  value: {
    getRandomValues(values) {
      for (let index = 0; index < values.length; index += 1) values[index] = 0x12345678;
      return values;
    },
  },
});

require(path.join(__dirname, '..', '..', 'archives', 'js_security_v3_0.1.4_20260527205706.js'));

const calls = [];
const signer = new ParamsSign({ appId: 'fixture-app' });
signer._debug = false;
signer._$cps = function cps(argument) {
  calls.push(['cps', argument]);
  return fixture.cps_result;
};
signer._$rds = function rds() {
  calls.push(['rds']);
  return 'R';
};
signer._$clt = function clt(timestamp) {
  calls.push(['clt', timestamp]);
  return fixture.clt_result;
};
signer._$ms = function ms(left, right) {
  calls.push(['ms', left, right]);
  return fixture.ms_result;
};

const out = signer._$sdnmd(fixture.argument);
process.stdout.write(JSON.stringify({ out, calls }));

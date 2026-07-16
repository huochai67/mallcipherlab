// ==UserScript==
// @name         PDD 商品数据解密助手
// @namespace    http://tampermonkey.net/
// @version      1.1
// @description  观察 PDD 每次请求的 key/IV、加密响应和页面已解密 JSON
// @match        https://mobile.pinduoduo.com/goods.html*
// @match        https://mobile.pinduoduo.com/*goods_id=*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    window.__pdd = {
        status: 'init',
        goods_id: null,
        encrypted: null,
        decrypted: null,
        keys: null,         // latest observed { key, iv }
        keyEvents: [],      // every _encryptionKeys assignment
        encryptedEvents: [],
        decryptedEvents: [],
        goods_name: null,
        price: null,
        skus: null,
        error: null
    };

    // 从 URL 提取 goods_id
    const m = window.location.href.match(/goods_id=(\d+)/);
    if (m) window.__pdd.goods_id = m[1];

    // _encryptionKeys belongs to the Axios config, not native fetch init.
    Object.defineProperty(Object.prototype, '_encryptionKeys', {
        configurable: true,
        enumerable: false,
        get: function() { return undefined; },
        set: function(value) {
            if (value && value.key && value.iv) {
                const event = {
                    index: window.__pdd.keyEvents.length,
                    time: Date.now(),
                    key: value.key,
                    iv: value.iv
                };
                window.__pdd.keys = { key: value.key, iv: value.iv };
                window.__pdd.keyEvents.push(event);
            }
            Object.defineProperty(this, '_encryptionKeys', {
                value,
                writable: true,
                enumerable: true,
                configurable: true
            });
        }
    });

    // Hook JSON.parse: 捕获加密和解密数据
    const _origParse = JSON.parse;
    JSON.parse = function(text, reviver) {
        const result = _origParse.call(this, text, reviver);
        if (result && typeof result === 'object') {
            if (result.encrypt_status === 3 && result.encrypt_info) {
                window.__pdd.encrypted = {
                    encrypt_info: result.encrypt_info,
                    server_time: result.server_time,
                    encrypt_status: result.encrypt_status
                };
                window.__pdd.encryptedEvents.push({
                    index: window.__pdd.encryptedEvents.length,
                    time: Date.now(),
                    ...window.__pdd.encrypted
                });
            }
            if (typeof text === 'string' && text.length > 1000 &&
                result.goods && result.goods.goods_id &&
                (result.destination_url || result.section_list)) {
                window.__pdd.decrypted = result;
                window.__pdd.decryptedEvents.push({
                    index: window.__pdd.decryptedEvents.length,
                    time: Date.now(),
                    data: result
                });
                window.__pdd.goods_name = result.goods?.goods_name;
                window.__pdd.price = {
                    min_group_price: result.price?.min_group_price,
                    line_price: result.price?.line_price
                };
                window.__pdd.skus = (result.sku || []).map(s => ({
                    sku_id: s.sku_id,
                    specs: s.specs,
                    group_price: s.group_price,
                    normal_price: s.normal_price,
                    quantity: s.quantity
                }));
                window.__pdd.status = 'ready';
            }
        }
        return result;
    };

    window.__pdd.status = 'hook_ready';
})();

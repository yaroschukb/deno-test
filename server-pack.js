const matchCache = {
};
const FIELD_CONTENT_REGEXP = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
const KEY_REGEXP = /(?:^|;) *([^=]*)=[^;]*/g;
const SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i;
function getPattern(name) {
    if (name in matchCache) {
        return matchCache[name];
    }
    return matchCache[name] = new RegExp(`(?:^|;) *${name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}=([^;]*)`);
}
function pushCookie(headers, cookie) {
    if (cookie.overwrite) {
        for(let i = headers.length - 1; i >= 0; i--){
            if (headers[i].indexOf(`${cookie.name}=`) === 0) {
                headers.splice(i, 1);
            }
        }
    }
    headers.push(cookie.toHeader());
}
function validateCookieProperty(key, value) {
    if (value && !FIELD_CONTENT_REGEXP.test(value)) {
        throw new TypeError(`The ${key} of the cookie (${value}) is invalid.`);
    }
}
class Cookie {
    domain;
    expires;
    httpOnly = true;
    maxAge;
    name;
    overwrite = false;
    path = "/";
    sameSite = false;
    secure = false;
    signed;
    value;
    constructor(name1, value1, attributes){
        validateCookieProperty("name", name1);
        validateCookieProperty("value", value1);
        this.name = name1;
        this.value = value1 ?? "";
        Object.assign(this, attributes);
        if (!this.value) {
            this.expires = new Date(0);
            this.maxAge = undefined;
        }
        validateCookieProperty("path", this.path);
        validateCookieProperty("domain", this.domain);
        if (this.sameSite && typeof this.sameSite === "string" && !SAME_SITE_REGEXP.test(this.sameSite)) {
            throw new TypeError(`The sameSite of the cookie ("${this.sameSite}") is invalid.`);
        }
    }
    toHeader() {
        let header = this.toString();
        if (this.maxAge) {
            this.expires = new Date(Date.now() + this.maxAge * 1000);
        }
        if (this.path) {
            header += `; path=${this.path}`;
        }
        if (this.expires) {
            header += `; expires=${this.expires.toUTCString()}`;
        }
        if (this.domain) {
            header += `; domain=${this.domain}`;
        }
        if (this.sameSite) {
            header += `; samesite=${this.sameSite === true ? "strict" : this.sameSite.toLowerCase()}`;
        }
        if (this.secure) {
            header += "; secure";
        }
        if (this.httpOnly) {
            header += "; httponly";
        }
        return header;
    }
    toString() {
        return `${this.name}=${this.value}`;
    }
}
class Cookies {
    #cookieKeys;
    #keys;
    #request;
    #response;
    #secure;
     #requestKeys() {
        if (this.#cookieKeys) {
            return this.#cookieKeys;
        }
        const result = this.#cookieKeys = [];
        const header = this.#request.headers.get("cookie");
        if (!header) {
            return result;
        }
        let matches;
        while(matches = KEY_REGEXP.exec(header)){
            const [, key] = matches;
            result.push(key);
        }
        return result;
    }
    constructor(request3, response1, options1 = {
    }){
        const { keys: keys2 , secure: secure3  } = options1;
        this.#keys = keys2;
        this.#request = request3;
        this.#response = response1;
        this.#secure = secure3;
    }
    delete(name, options = {
    }) {
        this.set(name, null, options);
        return true;
    }
    *entries() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value1 = this.get(key);
            if (value1) {
                yield [
                    key,
                    value1
                ];
            }
        }
    }
    forEach(callback, thisArg = null) {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value1 = this.get(key);
            if (value1) {
                callback.call(thisArg, key, value1, this);
            }
        }
    }
    get(name, options = {
    }) {
        const signed = options.signed ?? !!this.#keys;
        const nameSig = `${name}.sig`;
        const header = this.#request.headers.get("cookie");
        if (!header) {
            return;
        }
        const match = header.match(getPattern(name));
        if (!match) {
            return;
        }
        const [, value1] = match;
        if (!signed) {
            return value1;
        }
        const digest = this.get(nameSig, {
            signed: false
        });
        if (!digest) {
            return;
        }
        const data = `${name}=${value1}`;
        if (!this.#keys) {
            throw new TypeError("keys required for signed cookies");
        }
        const index = this.#keys.indexOf(data, digest);
        if (index < 0) {
            this.delete(nameSig, {
                path: "/",
                signed: false
            });
        } else {
            if (index) {
                this.set(nameSig, this.#keys.sign(data), {
                    signed: false
                });
            }
            return value1;
        }
    }
    *keys() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value1 = this.get(key);
            if (value1) {
                yield key;
            }
        }
    }
    set(name, value, options = {
    }) {
        const request1 = this.#request;
        const response1 = this.#response;
        const headers = [];
        for (const [key, value2] of response1.headers.entries()){
            if (key === "set-cookie") {
                headers.push(value2);
            }
        }
        const secure1 = this.#secure !== undefined ? this.#secure : request1.secure;
        const signed = options.signed ?? !!this.#keys;
        if (!secure1 && options.secure) {
            throw new TypeError("Cannot send secure cookie over unencrypted connection.");
        }
        const cookie = new Cookie(name, value, options);
        cookie.secure = options.secure ?? secure1;
        pushCookie(headers, cookie);
        if (signed) {
            if (!this.#keys) {
                throw new TypeError(".keys required for signed cookies.");
            }
            cookie.value = this.#keys.sign(cookie.toString());
            cookie.name += ".sig";
            pushCookie(headers, cookie);
        }
        response1.headers.delete("Set-Cookie");
        for (const header of headers){
            response1.headers.append("Set-Cookie", header);
        }
        return this;
    }
    *values() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value2 = this.get(key);
            if (value2) {
                yield value2;
            }
        }
    }
    *[Symbol.iterator]() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value2 = this.get(key);
            if (value2) {
                yield [
                    key,
                    value2
                ];
            }
        }
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect([
            ...this.entries()
        ])}`;
    }
}
function equals(a, b) {
    if (a.length !== b.length) return false;
    for(let i = 0; i < b.length; i++){
        if (a[i] !== b[i]) return false;
    }
    return true;
}
function concat(...buf) {
    let length = 0;
    for (const b of buf){
        length += b.length;
    }
    const output = new Uint8Array(length);
    let index = 0;
    for (const b1 of buf){
        output.set(b1, index);
        index += b1.length;
    }
    return output;
}
function copy(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
const base64abc = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "+",
    "/"
];
function encode(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i;
    const l = uint8.length;
    for(i = 2; i < l; i += 3){
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 3) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 15) << 2 | uint8[i] >> 6];
        result += base64abc[uint8[i] & 63];
    }
    if (i === l + 1) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 3) << 4];
        result += "==";
    }
    if (i === l) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 3) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 15) << 2];
        result += "=";
    }
    return result;
}
function decode(b64) {
    const binString = atob(b64);
    const size = binString.length;
    const bytes = new Uint8Array(size);
    for(let i = 0; i < size; i++){
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
}
let cachedTextDecoder = new TextDecoder("utf-8", {
    ignoreBOM: true,
    fatal: true
});
cachedTextDecoder.decode();
let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}
function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}
const heap = new Array(32).fill(undefined);
heap.push(undefined, null, true, false);
let heap_next = heap.length;
function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];
    heap[idx] = obj;
    return idx;
}
function getObject(idx) {
    return heap[idx];
}
function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}
function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}
let WASM_VECTOR_LEN = 0;
let cachedTextEncoder = new TextEncoder("utf-8");
const encodeString = function(arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
};
function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }
    let len = arg.length;
    let ptr = malloc(len);
    const mem = getUint8Memory0();
    let offset = 0;
    for(; offset < len; offset++){
        const code = arg.charCodeAt(offset);
        if (code > 127) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);
        offset += ret.written;
    }
    WASM_VECTOR_LEN = offset;
    return ptr;
}
function create_hash(algorithm) {
    var ptr0 = passStringToWasm0(algorithm, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.create_hash(ptr0, len0);
    return DenoHash.__wrap(ret);
}
function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}
function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
function update_hash(hash, data) {
    _assertClass(hash, DenoHash);
    var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.update_hash(hash.ptr, ptr0, len0);
}
let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}
function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
function digest_hash(hash) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(hash, DenoHash);
        wasm.digest_hash(retptr, hash.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    } finally{
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}
const DenoHashFinalization = new FinalizationRegistry((ptr)=>wasm.__wbg_denohash_free(ptr)
);
class DenoHash {
    static __wrap(ptr) {
        const obj = Object.create(DenoHash.prototype);
        obj.ptr = ptr;
        DenoHashFinalization.register(obj, obj.ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;
        DenoHashFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_denohash_free(ptr);
    }
}
const imports = {
    __wbindgen_placeholder__: {
        __wbindgen_string_new: function(arg0, arg1) {
            var ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_throw: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbindgen_rethrow: function(arg0) {
            throw takeObject(arg0);
        }
    }
};
const wasmModule = new WebAssembly.Module(decode("AGFzbQEAAAAB64CAgAAQYAAAYAF/AGABfwF/YAF/AX5gAn9/AGACf38Bf2ADf39/AGADf39/AX9gBH\
9/f38Bf2AFf39/f38AYAV/f39/fwF/YAZ/f39/f38Bf2AFf39/fn8AYAd/f39+f39/AX9gAn9+AGAC\
fn8BfwKMgYCAAAMYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fFV9fd2JpbmRnZW5fc3RyaW5nX25ldw\
AFGF9fd2JpbmRnZW5fcGxhY2Vob2xkZXJfXxBfX3diaW5kZ2VuX3Rocm93AAQYX193YmluZGdlbl9w\
bGFjZWhvbGRlcl9fEl9fd2JpbmRnZW5fcmV0aHJvdwABA8aBgIAAxAEGBgUEBAYCDAYEBA0EAQQEAQ\
cFBA4ECgQEBwQEBAQECwQEBAQEBAQEBAQEBAQEAQQEBAQEBAQEBAUHBAQEBAYGBgYEBAQPAQQEBAEE\
BAQEBgYGBgYEBAQEBAQGBAQGBAYEBAQEBAQEBAQGBAQEBAQEBAQEBgQEBAQEBAQECQUFAQEGBgYGBg\
QBBQAEBwcBBggBBgEBBwEBAQQBBwIBBwEBBQUCBQUGAQEBAQQABQIAAAUEAQMCAgICAgICAgICAgIC\
AAQBBIWAgIAAAXABcXEFg4CAgAABABEGiYCAgAABfwFBgIDAAAsHroGAgAAJBm1lbW9yeQIAE19fd2\
JnX2Rlbm9oYXNoX2ZyZWUAkAELY3JlYXRlX2hhc2gABQt1cGRhdGVfaGFzaACRAQtkaWdlc3RfaGFz\
aACNARFfX3diaW5kZ2VuX21hbGxvYwCeARJfX3diaW5kZ2VuX3JlYWxsb2MAoAEfX193YmluZGdlbl\
9hZGRfdG9fc3RhY2tfcG9pbnRlcgCwAQ9fX3diaW5kZ2VuX2ZyZWUArQEJnoGAgAABAEEBC3CnAcUB\
rwGmAbMBxgFdGGFNwQE4VVhlnwG9AXVTV2R0VDlZmQG/AWpWHjCTAcABT2I6WpoBa2AvR5UBuwFzLT\
KWAbwBclIaJ4MBwwFfGyyCAcIBXkM/RqsBuAF4QTQ2rAG5AXxEJCWqAbcBfkIoKqkBugF9PkV6MzV5\
IyZ7KSt3ogELITeKAb4BH44BO4sBpAGAAYEBtgGjAQqChIeAAMQBkVoCAX8ifiMAQYABayIDJAAgA0\
EAQYABEJ0BIQMgACkDOCEEIAApAzAhBSAAKQMoIQYgACkDICEHIAApAxghCCAAKQMQIQkgACkDCCEK\
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\
CnZzaiAeaiAiICVqIhsgAiAhc3EgIXNqIBtBGncgG0EVd3MgG0EHd3NqQfLxxbN8aiIeaiELIBwgCm\
ohCiAjIAlqIQkgICAIaiEIIB0gB2ogHmohByAbIAZqIQYgAiAFaiEFICEgBGohBCABQcAAaiIBIAxH\
DQALCyAAIAQ2AhwgACAFNgIYIAAgBjYCFCAAIAc2AhAgACAINgIMIAAgCTYCCCAAIAo2AgQgACALNg\
IAC7U7Agl/BH4jAEHgA2siAiQAIAIgATYCDCACIAA2AggCQAJAAkACQAJAAkACQAJAAkACQAJAAkAC\
QAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAk\
ACQAJAAkAgAUF9ag4HABITAhMDARMLIABBgIDAAEEDEI8BRQ0DIABBqIDAAEEDEI8BRQ0EIABB0IDA\
AEEDEI8BDRIgAkG6AWpCADcBACACQcIBakEAOwEAIAJBsAFqQRRqQgA3AgAgAkGwAWpBHGpCADcCAC\
ACQbABakEkakIANwIAIAJBsAFqQSxqQgA3AgAgAkGwAWpBNGpCADcCACACQbABakE8akEAOgAAIAJB\
7QFqQQA2AAAgAkHxAWpBADsAACACQfMBakEAOgAAIAJBwAA2ArABIAJBADsBtAEgAkEANgG2ASACQc\
gCaiACQbABakHEABCXARogAkHYAGoiAyACQcgCakE8aikCADcDACACQdAAaiIEIAJByAJqQTRqKQIA\
NwMAIAJByABqIgUgAkHIAmpBLGopAgA3AwAgAkHAAGoiBiACQcgCakEkaikCADcDACACQThqIgcgAk\
HIAmpBHGopAgA3AwAgAkEwaiIIIAJByAJqQRRqKQIANwMAIAJBIGpBCGoiCSACQdQCaikCADcDACAC\
IAIpAswCNwMgQeAAEAkiCkUNFSAKQQA2AgggCkIANwMAIAogAikDIDcCDCAKQRRqIAkpAwA3AgAgCk\
EcaiAIKQMANwIAIApBJGogBykDADcCACAKQSxqIAYpAwA3AgAgCkE0aiAFKQMANwIAIApBPGogBCkD\
ADcCACAKQcQAaiADKQMANwIAIApB1ABqQQApApibQDcCACAKQQApApCbQDcCTEHUgMAAIQRBACEDDC\
gLIABB+IDAAEEJEI8BRQ0EIABBqIHAAEEJEI8BRQ0FIABBvITAACABEI8BRQ0NIABB7ITAACABEI8B\
RQ0OIABBnIXAACABEI8BRQ0PIABBzIXAACABEI8BDREgAkG6AWpCADcBACACQcIBakEAOwEAIAJBxA\
FqQgA3AgAgAkHMAWpCADcCACACQdQBakIANwIAIAJB3AFqQgA3AgAgAkHkAWpCADcCACACQewBakEA\
OgAAIAJB7QFqQgA3AAAgAkH1AWpBADYAACACQfkBakEAOwAAIAJB+wFqQQA6AAAgAkHIADYCsAEgAk\
EAOwG0ASACQQA2AbYBIAJByAJqIAJBsAFqQcwAEJcBGiACQSBqIAJByAJqQQRyQcgAEJcBGkGYAhAJ\
IgpFDSIgCkEAQcwBEJ0BQcwBaiACQSBqQcgAEJcBGkHYhcAAIQRBACEDDCcLIABB/IHAAEEGEI8BRQ\
0FIABBqILAAEEGEI8BRQ0GIABB1ILAAEEGEI8BRQ0HIABBgIPAAEEGEI8BRQ0IIABB/IXAAEEGEI8B\
DRAgAkHlAmoiA0EAKQOQnUAiCzcAACACQd0CakEAKQOInUAiDDcAACACQdUCakEAKQOAnUAiDTcAAC\
ACQQApA/icQCIONwDNAkH4DhAJIgpFDSIgCkIANwMAIAogDjcDCCAKQRBqIA03AwAgCkEYaiAMNwMA\
IApBIGogCzcDACAKQShqQQBBwwAQnQEaIApBADoA8A4gCkGIAWogAykAADcAACAKQYMBaiACQcgCak\
EYaikAADcAACAKQfsAaiACQcgCakEQaikAADcAACAKQfMAaiACQdACaikAADcAACAKIAIpAMgCNwBr\
QYSGwAAhBEEAIQMMJgsgACkAAELz0IWb08WMmTRRDQggACkAAELz0IWb08XMmjZRDQkgACkAAELz0I\
Wb0+WMnDRRDQogACkAAELz0IWb06XNmDJSDQ8gAkG6AWpCADcBACACQcIBakEAOwEAIAJBxAFqQgA3\
AgAgAkHMAWpCADcCACACQdQBakIANwIAIAJB3AFqQgA3AgAgAkHkAWpCADcCACACQewBakEAOgAAIA\
JB7QFqQgA3AAAgAkH1AWpBADYAACACQfkBakEAOwAAIAJB+wFqQQA6AAAgAkHIADYCsAEgAkEAOwG0\
ASACQQA2AbYBIAJByAJqIAJBsAFqQcwAEJcBGiACQSBqIAJByAJqQQRyQcgAEJcBGkGYAhAJIgpFDR\
wgCkEAQcwBEJ0BQcwBaiACQSBqQcgAEJcBGkGYhMAAIQRBACEDDCULIAJBugFqIgpCADcBACACQcIB\
aiIEQQA7AQAgAkEQNgKwASACQQA7AbQBIAJBADYBtgEgAkHIAmpBEGoiBSACQbABakEQaiIGKAIANg\
IAIAJByAJqQQhqIgMgAkGwAWpBCGoiBykDADcDACACQSBqQQhqIgggAkHIAmpBDGoiCSkCADcDACAC\
IAIpA7ABNwPIAiACIAIpAswCNwMgIApCADcBACAEQQA7AQAgAkEQNgKwASACQQA7AbQBIAJBADYBtg\
EgBSAGKAIANgIAIAMgBykDADcDACACIAIpA7ABNwPIAiACQRBqQQhqIgQgCSkCADcDACACIAIpAswC\
NwMQIAMgCCkDADcDACACIAIpAyA3A8gCQdQAEAkiCkUNDyAKQQA2AgAgCiACKQPIAjcCBCAKQgA3Ah\
QgCiACKQMQNwJEIApBHGpCADcCACAKQSRqQgA3AgAgCkEsakIANwIAIApBNGpCADcCACAKQTxqQgA3\
AgAgCkEMaiADKQMANwIAIApBzABqIAQpAwA3AgBBhIDAACEEQQAhAwwkCyACQboBakIANwEAIAJBwg\
FqQQA7AQAgAkGwAWpBFGpCADcCACACQbABakEcakIANwIAIAJBsAFqQSRqQgA3AgAgAkGwAWpBLGpC\
ADcCACACQbABakE0akIANwIAIAJBsAFqQTxqQQA6AAAgAkHtAWpBADYAACACQfEBakEAOwAAIAJB8w\
FqQQA6AAAgAkHAADYCsAEgAkEAOwG0ASACQQA2AbYBIAJByAJqIAJBsAFqQcQAEJcBGiACQdgAaiID\
IAJByAJqQTxqKQIANwMAIAJB0ABqIgQgAkHIAmpBNGopAgA3AwAgAkHIAGoiBSACQcgCakEsaikCAD\
cDACACQcAAaiIGIAJByAJqQSRqKQIANwMAIAJBOGoiByACQcgCakEcaikCADcDACACQTBqIgggAkHI\
AmpBFGopAgA3AwAgAkEgakEIaiIJIAJB1AJqKQIANwMAIAIgAikCzAI3AyBB4AAQCSIKRQ0PIApBAD\
YCCCAKQgA3AwAgCiACKQMgNwIMIApBFGogCSkDADcCACAKQRxqIAgpAwA3AgAgCkEkaiAHKQMANwIA\
IApBLGogBikDADcCACAKQTRqIAUpAwA3AgAgCkE8aiAEKQMANwIAIApBxABqIAMpAwA3AgAgCkHUAG\
pBACkCmJtANwIAIApBACkCkJtANwJMQayAwAAhBEEAIQMMIwsgAkG6AWpCADcBACACQcIBakEAOwEA\
IAJBsAFqQRRqQgA3AgAgAkGwAWpBHGpCADcCACACQbABakEkakIANwIAIAJBsAFqQSxqQgA3AgAgAk\
GwAWpBNGpCADcCACACQbABakE8akEAOgAAIAJB7QFqQQA2AAAgAkHxAWpBADsAACACQfMBakEAOgAA\
IAJBwAA2ArABIAJBADsBtAEgAkEANgG2ASACQcgCaiACQbABakHEABCXARogAkEgakE4aiIDIAJByA\
JqQTxqKQIANwMAIAJBIGpBMGoiBCACQcgCakE0aikCADcDACACQSBqQShqIgUgAkHIAmpBLGopAgA3\
AwAgAkHAAGoiBiACQcgCakEkaikCADcDACACQSBqQRhqIgcgAkHIAmpBHGopAgA3AwAgAkEgakEQai\
IIIAJByAJqQRRqKQIANwMAIAJBIGpBCGoiCSACQdQCaikCADcDACACIAIpAswCNwMgQeAAEAkiCkUN\
ECAKQgA3AwAgCkEANgIcIAogAikDIDcCICAKQQApA8ibQDcDCCAKQRBqQQApA9CbQDcDACAKQRhqQQ\
AoAtibQDYCACAKQShqIAkpAwA3AgAgCkEwaiAIKQMANwIAIApBOGogBykDADcCACAKQcAAaiAGKQMA\
NwIAIApByABqIAUpAwA3AgAgCkHQAGogBCkDADcCACAKQdgAaiADKQMANwIAQYSBwAAhBEEAIQMMIg\
sgAkG6AWpCADcBACACQcIBakEAOwEAIAJBsAFqQRRqQgA3AgAgAkGwAWpBHGpCADcCACACQbABakEk\
akIANwIAIAJBsAFqQSxqQgA3AgAgAkGwAWpBNGpCADcCACACQbABakE8akEAOgAAIAJB7QFqQQA2AA\
AgAkHxAWpBADsAACACQfMBakEAOgAAIAJBwAA2ArABIAJBADsBtAEgAkEANgG2ASACQcgCaiACQbAB\
akHEABCXARogAkHYAGoiAyACQcgCakE8aikCADcDACACQdAAaiIEIAJByAJqQTRqKQIANwMAIAJBIG\
pBKGoiBSACQcgCakEsaikCADcDACACQSBqQSBqIgYgAkHIAmpBJGopAgA3AwAgAkEgakEYaiIHIAJB\
yAJqQRxqKQIANwMAIAJBIGpBEGoiCCACQcgCakEUaikCADcDACACQSBqQQhqIgkgAkHUAmopAgA3Aw\
AgAiACKQLMAjcDIEH4ABAJIgpFDRAgCkIANwMAIApBADYCMCAKIAIpAyA3AjQgCkEAKQOgm0A3Awgg\
CkEQakEAKQOom0A3AwAgCkEYakEAKQOwm0A3AwAgCkEgakEAKQO4m0A3AwAgCkEoakEAKQPAm0A3Aw\
AgCkE8aiAJKQMANwIAIApBxABqIAgpAwA3AgAgCkHMAGogBykDADcCACAKQdQAaiAGKQMANwIAIApB\
3ABqIAUpAwA3AgAgCkHkAGogBCkDADcCACAKQewAaiADKQMANwIAQbSBwAAhBEEAIQMMIQsgAkG6AW\
pCADcBACACQcIBakEAOwEAIAJBsAFqQRRqQgA3AgAgAkGwAWpBHGpCADcCACACQbABakEkakIANwIA\
IAJBsAFqQSxqQgA3AgAgAkGwAWpBNGpCADcCACACQbABakE8akEAOgAAIAJB7QFqQQA2AAAgAkHxAW\
pBADsAACACQfMBakEAOgAAIAJBwAA2ArABIAJBADsBtAEgAkEANgG2ASACQcgCaiACQbABakHEABCX\
ARogAkHYAGoiAyACQcgCakE8aikCADcDACACQdAAaiIEIAJByAJqQTRqKQIANwMAIAJByABqIgUgAk\
HIAmpBLGopAgA3AwAgAkHAAGoiBiACQcgCakEkaikCADcDACACQThqIgcgAkHIAmpBHGopAgA3AwAg\
AkEwaiIIIAJByAJqQRRqKQIANwMAIAJBIGpBCGoiCSACQdQCaikCADcDACACIAIpAswCNwMgQfAAEA\
kiCkUNECAKIAIpAyA3AgwgCkEANgIIIApCADcDACAKQRxqIAgpAwA3AgAgCkEUaiAJKQMANwIAIApB\
JGogBykDADcCACAKQSxqIAYpAwA3AgAgCkE0aiAFKQMANwIAIApBPGogBCkDADcCACAKQcQAaiADKQ\
MANwIAIApB1ABqQQApAuCcQDcCACAKQQApAticQDcCTCAKQeQAakEAKQLwnEA3AgAgCkHcAGpBACkC\
6JxANwIAQYSCwAAhBEEAIQMMIAsgAkG6AWpCADcBACACQcIBakEAOwEAIAJBsAFqQRRqQgA3AgAgAk\
GwAWpBHGpCADcCACACQbABakEkakIANwIAIAJBsAFqQSxqQgA3AgAgAkGwAWpBNGpCADcCACACQbAB\
akE8akEAOgAAIAJB7QFqQQA2AAAgAkHxAWpBADsAACACQfMBakEAOgAAIAJBwAA2ArABIAJBADsBtA\
EgAkEANgG2ASACQcgCaiACQbABakHEABCXARogAkHYAGoiAyACQcgCakE8aikCADcDACACQdAAaiIE\
IAJByAJqQTRqKQIANwMAIAJByABqIgUgAkHIAmpBLGopAgA3AwAgAkHAAGoiBiACQcgCakEkaikCAD\
cDACACQThqIgcgAkHIAmpBHGopAgA3AwAgAkEwaiIIIAJByAJqQRRqKQIANwMAIAJBIGpBCGoiCSAC\
QdQCaikCADcDACACIAIpAswCNwMgQfAAEAkiCkUNECAKIAIpAyA3AgwgCkEANgIIIApCADcDACAKQR\
xqIAgpAwA3AgAgCkEUaiAJKQMANwIAIApBJGogBykDADcCACAKQSxqIAYpAwA3AgAgCkE0aiAFKQMA\
NwIAIApBPGogBCkDADcCACAKQcQAaiADKQMANwIAIApB1ABqQQApA4CdQDcCACAKQQApA/icQDcCTC\
AKQeQAakEAKQOQnUA3AgAgCkHcAGpBACkDiJ1ANwIAQbCCwAAhBEEAIQMMHwsgAkEANgKwASACQbAB\
akEEciEDQQAhCgNAIAMgCmpBADoAACACIAIoArABQQFqNgKwASAKQQFqIgpBgAFHDQALIAJByAJqIA\
JBsAFqQYQBEJcBGiACQSBqIAJByAJqQQRyQYABEJcBGkHYARAJIgpFDRAgCkIANwMIIApCADcDACAK\
QQA2AlAgCkEAKQOYnUA3AxAgCkEYakEAKQOgnUA3AwAgCkEgakEAKQOonUA3AwAgCkEoakEAKQOwnU\
A3AwAgCkEwakEAKQO4nUA3AwAgCkE4akEAKQPAnUA3AwAgCkHAAGpBACkDyJ1ANwMAIApByABqQQAp\
A9CdQDcDACAKQdQAaiACQSBqQYABEJcBGkHcgsAAIQRBACEDDB4LIAJBADYCsAEgAkGwAWpBBHIhA0\
EAIQoDQCADIApqQQA6AAAgAiACKAKwAUEBajYCsAEgCkEBaiIKQYABRw0ACyACQcgCaiACQbABakGE\
ARCXARogAkEgaiACQcgCakEEckGAARCXARpB2AEQCSIKRQ0QIApCADcDCCAKQgA3AwAgCkEANgJQIA\
pBACkD2J1ANwMQIApBGGpBACkD4J1ANwMAIApBIGpBACkD6J1ANwMAIApBKGpBACkD8J1ANwMAIApB\
MGpBACkD+J1ANwMAIApBOGpBACkDgJ5ANwMAIApBwABqQQApA4ieQDcDACAKQcgAakEAKQOQnkA3Aw\
AgCkHUAGogAkEgakGAARCXARpBiIPAACEEQQAhAwwdCyACQQA2ArABQQQhCgNAIAJBsAFqIApqQQA6\
AAAgAiACKAKwAUEBajYCsAEgCkEBaiIKQZQBRw0ACyACQcgCaiACQbABakGUARCXARogAkEgaiACQc\
gCakEEckGQARCXARpB4AIQCSIKRQ0QIApBAEHMARCdAUHMAWogAkEgakGQARCXARpBrIPAACEEQQAh\
AwwcCyACQQA2ArABQQQhCgNAIAJBsAFqIApqQQA6AAAgAiACKAKwAUEBajYCsAEgCkEBaiIKQYwBRw\
0ACyACQcgCaiACQbABakGMARCXARogAkEgaiACQcgCakEEckGIARCXARpB2AIQCSIKRQ0QIApBAEHM\
ARCdAUHMAWogAkEgakGIARCXARpB0IPAACEEQQAhAwwbCyACQQA2ArABQQQhCgNAIAJBsAFqIApqQQ\
A6AAAgAiACKAKwAUEBajYCsAEgCkEBaiIKQewARw0ACyACQcgCaiACQbABakHsABCXARogAkEgaiAC\
QcgCakEEckHoABCXARpBuAIQCSIKRQ0QIApBAEHMARCdAUHMAWogAkEgakHoABCXARpB9IPAACEEQQ\
AhAwwaCyACQQA2ArABQQQhCgNAIAJBsAFqIApqQQA6AAAgAiACKAKwAUEBajYCsAEgCkEBaiIKQZQB\
Rw0ACyACQcgCaiACQbABakGUARCXARogAkEgaiACQcgCakEEckGQARCXARpB4AIQCSIKRQ0RIApBAE\
HMARCdAUHMAWogAkEgakGQARCXARpByITAACEEQQAhAwwZCyACQQA2ArABQQQhCgNAIAJBsAFqIApq\
QQA6AAAgAiACKAKwAUEBajYCsAEgCkEBaiIKQYwBRw0ACyACQcgCaiACQbABakGMARCXARogAkEgai\
ACQcgCakEEckGIARCXARpB2AIQCSIKRQ0RIApBAEHMARCdAUHMAWogAkEgakGIARCXARpB+ITAACEE\
QQAhAwwYCyACQQA2ArABQQQhCgNAIAJBsAFqIApqQQA6AAAgAiACKAKwAUEBajYCsAEgCkEBaiIKQe\
wARw0ACyACQcgCaiACQbABakHsABCXARogAkEgaiACQcgCakEEckHoABCXARpBuAIQCSIKRQ0RIApB\
AEHMARCdAUHMAWogAkEgakHoABCXARpBqIXAACEEQQAhAwwXCyAAKAAAQfPQhYsDRg0VCyACQQE2Ai\
QgAiACQQhqNgIgQTgQCSIKRQ0SIAJCODcCtAEgAiAKNgKwASACIAJBsAFqNgIQIAJB3AJqQQE2AgAg\
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\
QQp3IhtzakGh1+f2BmpBDXcgHmoiHCARQX9zciAXQQp3IhdzakGh1+f2BmpBBncgG2oiHkEKdyIfai\
AaIBNBf3NxaiATIBZxakHp7bXTB2pBD3cgGGoiEkF/c3FqIBIgE3FqQenttdMHakEFdyAaaiITQX9z\
cWogEyAScWpB6e210wdqQQh3IB1qIhZBCnciGGogDyAZaiATQQp3IhogECAdaiASQQp3Ih0gFkF/c3\
FqIBYgE3FqQenttdMHakELdyAZaiISQX9zcWogEiAWcWpB6e210wdqQQ53IB1qIhNBCnciGSABIBpq\
IBJBCnciICAHIB1qIBggE0F/c3FqIBMgEnFqQenttdMHakEOdyAaaiISQX9zcWogEiATcWpB6e210w\
dqQQZ3IBhqIhNBf3NxaiATIBJxakHp7bXTB2pBDncgIGoiFkEKdyIYaiANIBlqIBNBCnciGiACICBq\
IBJBCnciHSAWQX9zcWogFiATcWpB6e210wdqQQZ3IBlqIhJBf3NxaiASIBZxakHp7bXTB2pBCXcgHW\
oiE0EKdyIZIAYgGmogEkEKdyIgIAggHWogGCATQX9zcWogEyAScWpB6e210wdqQQx3IBpqIhJBf3Nx\
aiASIBNxakHp7bXTB2pBCXcgGGoiE0F/c3FqIBMgEnFqQenttdMHakEMdyAgaiIWQQp3IhhqIA4gEk\
EKdyIaaiAYIAwgGWogE0EKdyIdIAQgIGogGiAWQX9zcWogFiATcWpB6e210wdqQQV3IBlqIhJBf3Nx\
aiASIBZxakHp7bXTB2pBD3cgGmoiE0F/c3FqIBMgEnFqQenttdMHakEIdyAdaiIZIAogDyAFIA0gHE\
EKdyIWaiACIBFBCnciEWogByAXaiAGIBtqIB4gHEF/c3IgEXNqQaHX5/YGakEFdyAXaiIXIB5Bf3Ny\
IBZzakGh1+f2BmpBDHcgEWoiESAXQX9zciAfc2pBodfn9gZqQQd3IBZqIhogEUF/c3IgF0EKdyIbc2\
pBodfn9gZqQQV3IB9qIhxBCnciFmogByARQQp3IhdqIBUgEGogGiAXQX9zcWogHCAXcWpB3Pnu+Hhq\
QQt3IBtqIhUgFkF/c3FqIAsgG2ogHCAaQQp3IhFBf3NxaiAVIBFxakHc+e74eGpBDHcgF2oiGiAWcW\
pB3Pnu+HhqQQ53IBFqIhsgGkEKdyIXQX9zcWogDCARaiAaIBVBCnciEUF/c3FqIBsgEXFqQdz57vh4\
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\
cyASIBFzIBZzIA8gDXMgC3MgAnNBAXciIHNBAXciIXNBAXciInNBAXciI3NBAXciJHNBAXciJXNBAX\
ciJnNBAXciJyAdICFzIAIgFnMgIXMgFCALcyAgcyAdc0EBdyIoc0EBdyIpcyAcICBzIChzIB9zQQF3\
IipzQQF3IitzIB8gKXMgK3MgHiAocyAqcyAnc0EBdyIsc0EBdyItcyAmICpzICxzICUgH3MgJ3MgJC\
AecyAmcyAjIBtzICVzICIgGnMgJHMgISAZcyAjcyAgIBdzICJzIClzQQF3Ii5zQQF3Ii9zQQF3IjBz\
QQF3IjFzQQF3IjJzQQF3IjNzQQF3IjRzQQF3IjUgKyAvcyApICNzIC9zICggInMgLnMgK3NBAXciNn\
NBAXciN3MgKiAucyA2cyAtc0EBdyI4c0EBdyI5cyAtIDdzIDlzICwgNnMgOHMgNXNBAXciOnNBAXci\
O3MgNCA4cyA6cyAzIC1zIDVzIDIgLHMgNHMgMSAncyAzcyAwICZzIDJzIC8gJXMgMXMgLiAkcyAwcy\
A3c0EBdyI8c0EBdyI9c0EBdyI+c0EBdyI/c0EBdyJAc0EBdyJBc0EBdyJCc0EBdyJDIDkgPXMgNyAx\
cyA9cyA2IDBzIDxzIDlzQQF3IkRzQQF3IkVzIDggPHMgRHMgO3NBAXciRnNBAXciR3MgOyBFcyBHcy\
A6IERzIEZzIENzQQF3IkhzQQF3IklzIEIgRnMgSHMgQSA7cyBDcyBAIDpzIEJzID8gNXMgQXMgPiA0\
cyBAcyA9IDNzID9zIDwgMnMgPnMgRXNBAXciSnNBAXciS3NBAXciTHNBAXciTXNBAXciTnNBAXciT3\
NBAXciUHNBAXdqIEYgSnMgRCA+cyBKcyBHc0EBdyJRcyBJc0EBdyJSIEUgP3MgS3MgUXNBAXciUyBM\
IEEgOiA5IDwgMSAmIB8gKCAhIBcgEyAQIAhBHnciVGogDiAFIAdBHnciECAGcyAIcSAGc2pqIA0gBC\
AIQQV3aiAGIAVzIAdxIAVzampBmfOJ1AVqIg5BBXdqQZnzidQFaiJVQR53IgggDkEedyINcyAGIA9q\
IA4gVCAQc3EgEHNqIFVBBXdqQZnzidQFaiIOcSANc2ogECARaiBVIA0gVHNxIFRzaiAOQQV3akGZ84\
nUBWoiEEEFd2pBmfOJ1AVqIhFBHnciD2ogDCAIaiARIBBBHnciEyAOQR53IgxzcSAMc2ogEiANaiAM\
IAhzIBBxIAhzaiARQQV3akGZ84nUBWoiEUEFd2pBmfOJ1AVqIhJBHnciCCARQR53IhBzIAogDGogES\
APIBNzcSATc2ogEkEFd2pBmfOJ1AVqIgpxIBBzaiALIBNqIBAgD3MgEnEgD3NqIApBBXdqQZnzidQF\
aiIMQQV3akGZ84nUBWoiD0EedyILaiAVIApBHnciF2ogCyAMQR53IhNzIBQgEGogDCAXIAhzcSAIc2\
ogD0EFd2pBmfOJ1AVqIhRxIBNzaiAWIAhqIA8gEyAXc3EgF3NqIBRBBXdqQZnzidQFaiIVQQV3akGZ\
84nUBWoiFiAVQR53IhcgFEEedyIIc3EgCHNqIAIgE2ogCCALcyAVcSALc2ogFkEFd2pBmfOJ1AVqIh\
RBBXdqQZnzidQFaiIVQR53IgJqIBkgFkEedyILaiACIBRBHnciE3MgGCAIaiAUIAsgF3NxIBdzaiAV\
QQV3akGZ84nUBWoiGHEgE3NqICAgF2ogEyALcyAVcSALc2ogGEEFd2pBmfOJ1AVqIghBBXdqQZnzid\
QFaiILIAhBHnciFCAYQR53IhdzcSAXc2ogHCATaiAIIBcgAnNxIAJzaiALQQV3akGZ84nUBWoiAkEF\
d2pBmfOJ1AVqIhhBHnciCGogHSAUaiACQR53IhMgC0EedyILcyAYc2ogGiAXaiALIBRzIAJzaiAYQQ\
V3akGh1+f2BmoiAkEFd2pBodfn9gZqIhdBHnciGCACQR53IhRzICIgC2ogCCATcyACc2ogF0EFd2pB\
odfn9gZqIgJzaiAbIBNqIBQgCHMgF3NqIAJBBXdqQaHX5/YGaiIXQQV3akGh1+f2BmoiCEEedyILai\
AeIBhqIBdBHnciEyACQR53IgJzIAhzaiAjIBRqIAIgGHMgF3NqIAhBBXdqQaHX5/YGaiIXQQV3akGh\
1+f2BmoiGEEedyIIIBdBHnciFHMgKSACaiALIBNzIBdzaiAYQQV3akGh1+f2BmoiAnNqICQgE2ogFC\
ALcyAYc2ogAkEFd2pBodfn9gZqIhdBBXdqQaHX5/YGaiIYQR53IgtqICUgCGogF0EedyITIAJBHnci\
AnMgGHNqIC4gFGogAiAIcyAXc2ogGEEFd2pBodfn9gZqIhdBBXdqQaHX5/YGaiIYQR53IgggF0Eedy\
IUcyAqIAJqIAsgE3MgF3NqIBhBBXdqQaHX5/YGaiICc2ogLyATaiAUIAtzIBhzaiACQQV3akGh1+f2\
BmoiF0EFd2pBodfn9gZqIhhBHnciC2ogMCAIaiAXQR53IhMgAkEedyICcyAYc2ogKyAUaiACIAhzIB\
dzaiAYQQV3akGh1+f2BmoiF0EFd2pBodfn9gZqIhhBHnciCCAXQR53IhRzICcgAmogCyATcyAXc2og\
GEEFd2pBodfn9gZqIhVzaiA2IBNqIBQgC3MgGHNqIBVBBXdqQaHX5/YGaiILQQV3akGh1+f2BmoiE0\
EedyICaiA3IAhqIAtBHnciFyAVQR53IhhzIBNxIBcgGHFzaiAsIBRqIBggCHMgC3EgGCAIcXNqIBNB\
BXdqQdz57vh4aiITQQV3akHc+e74eGoiFEEedyIIIBNBHnciC3MgMiAYaiATIAIgF3NxIAIgF3Fzai\
AUQQV3akHc+e74eGoiGHEgCCALcXNqIC0gF2ogFCALIAJzcSALIAJxc2ogGEEFd2pB3Pnu+HhqIhNB\
BXdqQdz57vh4aiIUQR53IgJqIDggCGogFCATQR53IhcgGEEedyIYc3EgFyAYcXNqIDMgC2ogGCAIcy\
ATcSAYIAhxc2ogFEEFd2pB3Pnu+HhqIhNBBXdqQdz57vh4aiIUQR53IgggE0EedyILcyA9IBhqIBMg\
AiAXc3EgAiAXcXNqIBRBBXdqQdz57vh4aiIYcSAIIAtxc2ogNCAXaiALIAJzIBRxIAsgAnFzaiAYQQ\
V3akHc+e74eGoiE0EFd2pB3Pnu+HhqIhRBHnciAmogRCAYQR53IhdqIAIgE0EedyIYcyA+IAtqIBMg\
FyAIc3EgFyAIcXNqIBRBBXdqQdz57vh4aiILcSACIBhxc2ogNSAIaiAUIBggF3NxIBggF3FzaiALQQ\
V3akHc+e74eGoiE0EFd2pB3Pnu+HhqIhQgE0EedyIXIAtBHnciCHNxIBcgCHFzaiA/IBhqIAggAnMg\
E3EgCCACcXNqIBRBBXdqQdz57vh4aiITQQV3akHc+e74eGoiFUEedyICaiA7IBRBHnciGGogAiATQR\
53IgtzIEUgCGogEyAYIBdzcSAYIBdxc2ogFUEFd2pB3Pnu+HhqIghxIAIgC3FzaiBAIBdqIAsgGHMg\
FXEgCyAYcXNqIAhBBXdqQdz57vh4aiITQQV3akHc+e74eGoiFCATQR53IhggCEEedyIXc3EgGCAXcX\
NqIEogC2ogEyAXIAJzcSAXIAJxc2ogFEEFd2pB3Pnu+HhqIgJBBXdqQdz57vh4aiIIQR53IgtqIEsg\
GGogAkEedyITIBRBHnciFHMgCHNqIEYgF2ogFCAYcyACc2ogCEEFd2pB1oOL03xqIgJBBXdqQdaDi9\
N8aiIXQR53IhggAkEedyIIcyBCIBRqIAsgE3MgAnNqIBdBBXdqQdaDi9N8aiICc2ogRyATaiAIIAtz\
IBdzaiACQQV3akHWg4vTfGoiF0EFd2pB1oOL03xqIgtBHnciE2ogUSAYaiAXQR53IhQgAkEedyICcy\
ALc2ogQyAIaiACIBhzIBdzaiALQQV3akHWg4vTfGoiF0EFd2pB1oOL03xqIhhBHnciCCAXQR53Igtz\
IE0gAmogEyAUcyAXc2ogGEEFd2pB1oOL03xqIgJzaiBIIBRqIAsgE3MgGHNqIAJBBXdqQdaDi9N8ai\
IXQQV3akHWg4vTfGoiGEEedyITaiBJIAhqIBdBHnciFCACQR53IgJzIBhzaiBOIAtqIAIgCHMgF3Nq\
IBhBBXdqQdaDi9N8aiIXQQV3akHWg4vTfGoiGEEedyIIIBdBHnciC3MgSiBAcyBMcyBTc0EBdyIVIA\
JqIBMgFHMgF3NqIBhBBXdqQdaDi9N8aiICc2ogTyAUaiALIBNzIBhzaiACQQV3akHWg4vTfGoiF0EF\
d2pB1oOL03xqIhhBHnciE2ogUCAIaiAXQR53IhQgAkEedyICcyAYc2ogSyBBcyBNcyAVc0EBdyIVIA\
tqIAIgCHMgF3NqIBhBBXdqQdaDi9N8aiIXQQV3akHWg4vTfGoiGEEedyIWIBdBHnciC3MgRyBLcyBT\
cyBSc0EBdyACaiATIBRzIBdzaiAYQQV3akHWg4vTfGoiAnNqIEwgQnMgTnMgFXNBAXcgFGogCyATcy\
AYc2ogAkEFd2pB1oOL03xqIhdBBXdqQdaDi9N8aiEIIBcgB2ohByAWIAVqIQUgAkEedyAGaiEGIAsg\
BGohBCABQcAAaiIBIAlHDQALCyAAIAQ2AhAgACAFNgIMIAAgBjYCCCAAIAc2AgQgACAINgIAC64tAg\
l/AX4CQAJAAkACQAJAAkACQAJAAkACQAJAIABB9AFLDQACQEEAKAL8o0AiAUEQIABBC2pBeHEgAEEL\
SRsiAkEDdiIDQR9xIgR2IgBBA3FFDQACQAJAIABBf3NBAXEgA2oiAkEDdCIEQYykwABqKAIAIgBBCG\
oiBSgCACIDIARBhKTAAGoiBEcNAEEAIAFBfiACd3E2AvyjQAwBCyADIAQ2AgwgBCADNgIICyAAIAJB\
A3QiAkEDcjYCBCAAIAJqIgAgACgCBEEBcjYCBCAFDwsgAkEAKAKMp0BNDQECQCAARQ0AAkACQEECIA\
R0IgNBACADa3IgACAEdHEiAEEAIABrcWgiA0EDdCIFQYykwABqKAIAIgBBCGoiBigCACIEIAVBhKTA\
AGoiBUcNAEEAIAFBfiADd3E2AvyjQAwBCyAEIAU2AgwgBSAENgIICyAAIAJBA3I2AgQgACACaiIEIA\
NBA3QiAyACayICQQFyNgIEIAAgA2ogAjYCAAJAQQAoAoynQCIARQ0AIABBA3YiAUEDdEGEpMAAaiED\
QQAoApSnQCEAAkACQEEAKAL8o0AiBUEBIAFBH3F0IgFxDQBBACAFIAFyNgL8o0AgAyEBDAELIAMoAg\
ghAQsgAyAANgIIIAEgADYCDCAAIAM2AgwgACABNgIIC0EAIAQ2ApSnQEEAIAI2AoynQCAGDwtBACgC\
gKRAIgBFDQEgAEEAIABrcWhBAnRBjKbAAGooAgAiBSgCBEF4cSEDAkAgBSgCECIADQAgBUEUaigCAC\
EACyADIAJrIQQCQCAARQ0AA0AgACgCBEF4cSACayIGIARJIQECQCAAKAIQIgMNACAAQRRqKAIAIQML\
IAYgBCABGyEEIAAgBSABGyEFIAMhACADDQALCyAFKAIYIQcCQAJAIAUoAgwiAyAFRg0AIAUoAggiAC\
ADNgIMIAMgADYCCAwBCwJAIAVBFEEQIAVBFGoiAygCACIBG2ooAgAiAA0AQQAhAwwBCyADIAVBEGog\
ARshAQNAIAEhBgJAIAAiA0EUaiIBKAIAIgANACADQRBqIQEgAygCECEACyAADQALIAZBADYCAAsCQC\
AHRQ0AAkACQCAFKAIcQQJ0QYymwABqIgAoAgAgBUcNACAAIAM2AgAgAw0BQQBBACgCgKRAQX4gBSgC\
HHdxNgKApEAMAgsgB0EQQRQgBygCECAFRhtqIAM2AgAgA0UNAQsgAyAHNgIYAkAgBSgCECIARQ0AIA\
MgADYCECAAIAM2AhgLIAVBFGooAgAiAEUNACADQRRqIAA2AgAgACADNgIYCwJAAkAgBEEQTw0AIAUg\
BCACaiIAQQNyNgIEIAUgAGoiACAAKAIEQQFyNgIEDAELIAUgAkEDcjYCBCAFIAJqIgIgBEEBcjYCBC\
ACIARqIAQ2AgACQEEAKAKMp0AiAEUNACAAQQN2IgFBA3RBhKTAAGohA0EAKAKUp0AhAAJAAkBBACgC\
/KNAIgZBASABQR9xdCIBcQ0AQQAgBiABcjYC/KNAIAMhAQwBCyADKAIIIQELIAMgADYCCCABIAA2Ag\
wgACADNgIMIAAgATYCCAtBACACNgKUp0BBACAENgKMp0ALIAVBCGoPC0EAIQMgAEHN/3tPDQYgAEEL\
aiIAQXhxIQJBACgCgKRAIghFDQBBACEHAkAgAEEIdiIARQ0AQR8hByACQf///wdLDQAgAkEGIABnIg\
BrQR9xdkEBcSAAQQF0a0E+aiEHC0EAIAJrIQMCQAJAAkAgB0ECdEGMpsAAaigCACIARQ0AQQAhBCAC\
QQBBGSAHQQF2a0EfcSAHQR9GG3QhAUEAIQUDQAJAIAAoAgRBeHEiBiACSQ0AIAYgAmsiBiADTw0AIA\
YhAyAAIQUgBg0AQQAhAyAAIQUMAwsgAEEUaigCACIGIAQgBiAAIAFBHXZBBHFqQRBqKAIAIgBHGyAE\
IAYbIQQgAUEBdCEBIAANAAsCQCAERQ0AIAQhAAwCCyAFDQILQQAhBSAIQQIgB0EfcXQiAEEAIABrcn\
EiAEUNAiAAQQAgAGtxaEECdEGMpsAAaigCACIARQ0CCwNAIAAoAgRBeHEiBCACTyAEIAJrIgYgA0lx\
IQECQCAAKAIQIgQNACAAQRRqKAIAIQQLIAAgBSABGyEFIAYgAyABGyEDIAQhACAEDQALIAVFDQELAk\
BBACgCjKdAIgAgAkkNACADIAAgAmtPDQELIAUoAhghByAFKAIMIgQgBUYNASAFKAIIIgAgBDYCDCAE\
IAA2AggMAgtBACgCjKdAIgAgAkkNBEEAKAKUp0AhAyAAIAJrIgRBEEkNAkEAIAQ2AoynQEEAIAMgAm\
oiATYClKdAIAEgBEEBcjYCBCADIABqIAQ2AgAgAyACQQNyNgIEDAMLAkAgBUEUQRAgBUEUaiIEKAIA\
IgEbaigCACIADQBBACEEDAELIAQgBUEQaiABGyEBA0AgASEGAkAgACIEQRRqIgEoAgAiAA0AIARBEG\
ohASAEKAIQIQALIAANAAsgBkEANgIACwJAIAdFDQACQAJAIAUoAhxBAnRBjKbAAGoiACgCACAFRw0A\
IAAgBDYCACAEDQFBAEEAKAKApEBBfiAFKAIcd3E2AoCkQAwCCyAHQRBBFCAHKAIQIAVGG2ogBDYCAC\
AERQ0BCyAEIAc2AhgCQCAFKAIQIgBFDQAgBCAANgIQIAAgBDYCGAsgBUEUaigCACIARQ0AIARBFGog\
ADYCACAAIAQ2AhgLAkAgA0EPSw0AIAUgAyACaiIAQQNyNgIEIAUgAGoiACAAKAIEQQFyNgIEDAcLIA\
UgAkEDcjYCBCAFIAJqIgIgA0EBcjYCBCACIANqIAM2AgACQCADQf8BSw0AIANBA3YiA0EDdEGEpMAA\
aiEAAkACQEEAKAL8o0AiBEEBIAN0IgNxDQBBACAEIANyNgL8o0AgACEDDAELIAAoAgghAwsgACACNg\
IIIAMgAjYCDCACIAA2AgwgAiADNgIIDAcLQR8hAAJAIANB////B0sNACADQQYgA0EIdmciAGtBH3F2\
QQFxIABBAXRrQT5qIQALIAJCADcCECACIAA2AhwgAEECdEGMpsAAaiEEAkACQEEAKAKApEAiAUEBIA\
BBH3F0IgZxDQBBACABIAZyNgKApEAgBCACNgIAIAIgBDYCGAwBCwJAIAQoAgAiASgCBEF4cSADRw0A\
IAEhAAwHCyADQQBBGSAAQQF2a0EfcSAAQR9GG3QhBAJAA0AgASAEQR12QQRxakEQaiIGKAIAIgBFDQ\
EgBEEBdCEEIAAhASAAKAIEQXhxIANGDQgMAAsLIAYgAjYCACACIAE2AhgLIAIgAjYCDCACIAI2AggM\
BgtBAEEANgKUp0BBAEEANgKMp0AgAyAAQQNyNgIEIAMgAGoiACAAKAIEQQFyNgIECyADQQhqDwtBAC\
gCkKdAIgAgAksNAUEAIQMgAkGvgARqIgRBEHZAACIAQX9GIgUNACAAQRB0IgFFDQBBAEEAKAKcp0BB\
ACAEQYCAfHEgBRsiBmoiADYCnKdAQQBBACgCoKdAIgMgACADIABLGzYCoKdAAkACQAJAAkBBACgCmK\
dAIgNFDQBBpKfAACEAA0AgACgCACIEIAAoAgQiBWogAUYNAiAAKAIIIgANAAwDCwsCQAJAQQAoArin\
QCIARQ0AIAAgAU0NAQtBACABNgK4p0ALQQBB/x82ArynQEEAIAY2AqinQEEAIAE2AqSnQEEAQYSkwA\
A2ApCkQEEAQYykwAA2ApikQEEAQYSkwAA2AoykQEEAQZSkwAA2AqCkQEEAQYykwAA2ApSkQEEAQZyk\
wAA2AqikQEEAQZSkwAA2ApykQEEAQaSkwAA2ArCkQEEAQZykwAA2AqSkQEEAQaykwAA2ArikQEEAQa\
SkwAA2AqykQEEAQbSkwAA2AsCkQEEAQaykwAA2ArSkQEEAQbykwAA2AsikQEEAQbSkwAA2ArykQEEA\
QQA2ArCnQEEAQcSkwAA2AtCkQEEAQbykwAA2AsSkQEEAQcSkwAA2AsykQEEAQcykwAA2AtikQEEAQc\
ykwAA2AtSkQEEAQdSkwAA2AuCkQEEAQdSkwAA2AtykQEEAQdykwAA2AuikQEEAQdykwAA2AuSkQEEA\
QeSkwAA2AvCkQEEAQeSkwAA2AuykQEEAQeykwAA2AvikQEEAQeykwAA2AvSkQEEAQfSkwAA2AoClQE\
EAQfSkwAA2AvykQEEAQfykwAA2AoilQEEAQfykwAA2AoSlQEEAQYSlwAA2ApClQEEAQYylwAA2Apil\
QEEAQYSlwAA2AoylQEEAQZSlwAA2AqClQEEAQYylwAA2ApSlQEEAQZylwAA2AqilQEEAQZSlwAA2Ap\
ylQEEAQaSlwAA2ArClQEEAQZylwAA2AqSlQEEAQaylwAA2ArilQEEAQaSlwAA2AqylQEEAQbSlwAA2\
AsClQEEAQaylwAA2ArSlQEEAQbylwAA2AsilQEEAQbSlwAA2ArylQEEAQcSlwAA2AtClQEEAQbylwA\
A2AsSlQEEAQcylwAA2AtilQEEAQcSlwAA2AsylQEEAQdSlwAA2AuClQEEAQcylwAA2AtSlQEEAQdyl\
wAA2AuilQEEAQdSlwAA2AtylQEEAQeSlwAA2AvClQEEAQdylwAA2AuSlQEEAQeylwAA2AvilQEEAQe\
SlwAA2AuylQEEAQfSlwAA2AoCmQEEAQeylwAA2AvSlQEEAQfylwAA2AoimQEEAQfSlwAA2AvylQEEA\
IAE2ApinQEEAQfylwAA2AoSmQEEAIAZBWGoiADYCkKdAIAEgAEEBcjYCBCABIABqQSg2AgRBAEGAgI\
ABNgK0p0AMAgsgACgCDCIHQQFxDQAgB0EBSw0AIAQgA0sNACABIANNDQAgACAFIAZqNgIEQQBBACgC\
mKdAIgBBD2pBeHEiA0F4ajYCmKdAQQAgACADa0EAKAKQp0AgBmoiBGpBCGoiATYCkKdAIANBfGogAU\
EBcjYCACAAIARqQSg2AgRBAEGAgIABNgK0p0AMAQtBAEEAKAK4p0AiACABIAAgAUkbNgK4p0AgASAG\
aiEEQaSnwAAhAAJAAkADQCAAKAIAIARGDQEgACgCCCIADQAMAgsLIAAoAgwNACAAIAE2AgAgACAAKA\
IEIAZqNgIEIAEgAkEDcjYCBCABIAJqIQAgBCABayACayECAkACQEEAKAKYp0AgBEcNAEEAIAA2Apin\
QEEAQQAoApCnQCACaiICNgKQp0AgACACQQFyNgIEDAELAkBBACgClKdAIARHDQBBACAANgKUp0BBAE\
EAKAKMp0AgAmoiAjYCjKdAIAAgAkEBcjYCBCAAIAJqIAI2AgAMAQsCQCAEKAIEIgNBA3FBAUcNAAJA\
AkAgA0F4cSIIQf8BSw0AAkAgBEEMaigCACIFIARBCGooAgAiBkcNAEEAQQAoAvyjQEF+IANBA3Z3cT\
YC/KNADAILIAYgBTYCDCAFIAY2AggMAQsgBCgCGCEJAkACQCAEKAIMIgUgBEYNACAEKAIIIgMgBTYC\
DCAFIAM2AggMAQsCQCAEQRRBECAEKAIUIgUbaigCACIDDQBBACEFDAELIARBFGogBEEQaiAFGyEGA0\
AgBiEHAkAgAyIFQRRqIgYoAgAiAw0AIAVBEGohBiAFKAIQIQMLIAMNAAsgB0EANgIACyAJRQ0AAkAC\
QCAEKAIcQQJ0QYymwABqIgMoAgAgBEcNACADIAU2AgAgBQ0BQQBBACgCgKRAQX4gBCgCHHdxNgKApE\
AMAgsgCUEQQRQgCSgCECAERhtqIAU2AgAgBUUNAQsgBSAJNgIYAkAgBCgCECIDRQ0AIAUgAzYCECAD\
IAU2AhgLIAQoAhQiA0UNACAFQRRqIAM2AgAgAyAFNgIYCyAIIAJqIQIgBCAIaiEECyAEIAQoAgRBfn\
E2AgQgACACQQFyNgIEIAAgAmogAjYCAAJAIAJB/wFLDQAgAkEDdiIDQQN0QYSkwABqIQICQAJAQQAo\
AvyjQCIEQQEgA3QiA3ENAEEAIAQgA3I2AvyjQCACIQMMAQsgAigCCCEDCyACIAA2AgggAyAANgIMIA\
AgAjYCDCAAIAM2AggMAQtBHyEDAkAgAkH///8HSw0AIAJBBiACQQh2ZyIDa0EfcXZBAXEgA0EBdGtB\
PmohAwsgAEIANwMQIAAgAzYCHCADQQJ0QYymwABqIQQCQAJAAkBBACgCgKRAIgVBASADQR9xdCIGcQ\
0AQQAgBSAGcjYCgKRAIAQgADYCACAAIAQ2AhgMAQsCQCAEKAIAIgUoAgRBeHEgAkcNACAFIQMMAgsg\
AkEAQRkgA0EBdmtBH3EgA0EfRht0IQQCQANAIAUgBEEddkEEcWpBEGoiBigCACIDRQ0BIARBAXQhBC\
ADIQUgAygCBEF4cSACRg0DDAALCyAGIAA2AgAgACAFNgIYCyAAIAA2AgwgACAANgIIDAELIAMoAggi\
AiAANgIMIAMgADYCCCAAQQA2AhggACADNgIMIAAgAjYCCAsgAUEIag8LQaSnwAAhAAJAA0ACQCAAKA\
IAIgQgA0sNACAEIAAoAgRqIgQgA0sNAgsgACgCCCIADQALAAtBACABNgKYp0BBACAGQVhqIgA2ApCn\
QCABIABBAXI2AgQgASAAakEoNgIEQQBBgICAATYCtKdAIAMgBEFgakF4cUF4aiIAIAAgA0EQakkbIg\
VBGzYCBEEAKQKkp0AhCiAFQRBqQQApAqynQDcCACAFIAo3AghBACAGNgKop0BBACABNgKkp0BBACAF\
QQhqNgKsp0BBAEEANgKwp0AgBUEcaiEAA0AgAEEHNgIAIAQgAEEEaiIASw0ACyAFIANGDQAgBSAFKA\
IEQX5xNgIEIAMgBSADayIBQQFyNgIEIAUgATYCAAJAIAFB/wFLDQAgAUEDdiIEQQN0QYSkwABqIQAC\
QAJAQQAoAvyjQCIBQQEgBHQiBHENAEEAIAEgBHI2AvyjQCAAIQQMAQsgACgCCCEECyAAIAM2AgggBC\
ADNgIMIAMgADYCDCADIAQ2AggMAQtBHyEAAkAgAUH///8HSw0AIAFBBiABQQh2ZyIAa0EfcXZBAXEg\
AEEBdGtBPmohAAsgA0IANwIQIANBHGogADYCACAAQQJ0QYymwABqIQQCQAJAAkBBACgCgKRAIgVBAS\
AAQR9xdCIGcQ0AQQAgBSAGcjYCgKRAIAQgAzYCACADQRhqIAQ2AgAMAQsCQCAEKAIAIgUoAgRBeHEg\
AUcNACAFIQAMAgsgAUEAQRkgAEEBdmtBH3EgAEEfRht0IQQCQANAIAUgBEEddkEEcWpBEGoiBigCAC\
IARQ0BIARBAXQhBCAAIQUgACgCBEF4cSABRg0DDAALCyAGIAM2AgAgA0EYaiAFNgIACyADIAM2Agwg\
AyADNgIIDAELIAAoAggiBCADNgIMIAAgAzYCCCADQRhqQQA2AgAgAyAANgIMIAMgBDYCCAtBACEDQQ\
AoApCnQCIAIAJNDQBBACAAIAJrIgM2ApCnQEEAQQAoApinQCIAIAJqIgQ2ApinQCAEIANBAXI2AgQg\
ACACQQNyNgIEIABBCGohAwsgAw8LQQAgACACayIDNgKQp0BBAEEAKAKYp0AiACACaiIENgKYp0AgBC\
ADQQFyNgIEIAAgAkEDcjYCBCAAQQhqDwsgACgCCCIDIAI2AgwgACACNgIIIAJBADYCGCACIAA2Agwg\
AiADNgIICyAFQQhqC5UbASB/IAAgACgCACABKAAAIgVqIAAoAhAiBmoiByABKAAEIghqIAcgA6dzQR\
B3IglB58yn0AZqIgogBnNBFHciC2oiDCABKAAgIgZqIAAoAgQgASgACCIHaiAAKAIUIg1qIg4gASgA\
DCIPaiAOIANCIIinc0EQdyIOQYXdntt7aiIQIA1zQRR3Ig1qIhEgDnNBGHciEiAQaiITIA1zQRl3Ih\
RqIhUgASgAJCINaiAVIAAoAgwgASgAGCIOaiAAKAIcIhZqIhcgASgAHCIQaiAXIARB/wFxc0EQdCAX\
QRB2ciIXQbrqv6p6aiIYIBZzQRR3IhZqIhkgF3NBGHciGnNBEHciGyAAKAIIIAEoABAiF2ogACgCGC\
IcaiIVIAEoABQiBGogFSACQf8BcXNBEHQgFUEQdnIiFUHy5rvjA2oiAiAcc0EUdyIcaiIdIBVzQRh3\
Ih4gAmoiH2oiICAUc0EUdyIUaiIhIAdqIBkgASgAOCIVaiAMIAlzQRh3IgwgCmoiGSALc0EZdyIJai\
IKIAEoADwiAmogCiAec0EQdyIKIBNqIgsgCXNBFHciCWoiEyAKc0EYdyIeIAtqIiIgCXNBGXciI2oi\
CyAOaiALIBEgASgAKCIJaiAfIBxzQRl3IhFqIhwgASgALCIKaiAcIAxzQRB3IgwgGiAYaiIYaiIaIB\
FzQRR3IhFqIhwgDHNBGHciDHNBEHciHyAdIAEoADAiC2ogGCAWc0EZdyIWaiIYIAEoADQiAWogGCAS\
c0EQdyISIBlqIhggFnNBFHciFmoiGSASc0EYdyISIBhqIhhqIh0gI3NBFHciI2oiJCAIaiAcIA9qIC\
EgG3NBGHciGyAgaiIcIBRzQRl3IhRqIiAgCWogICASc0EQdyISICJqIiAgFHNBFHciFGoiISASc0EY\
dyISICBqIiAgFHNBGXciFGoiIiAKaiAiIBMgF2ogGCAWc0EZdyITaiIWIAFqIBYgG3NBEHciFiAMIB\
pqIgxqIhggE3NBFHciE2oiGiAWc0EYdyIWc0EQdyIbIBkgEGogDCARc0EZdyIMaiIRIAVqIBEgHnNB\
EHciESAcaiIZIAxzQRR3IgxqIhwgEXNBGHciESAZaiIZaiIeIBRzQRR3IhRqIiIgD2ogGiACaiAkIB\
9zQRh3IhogHWoiHSAjc0EZdyIfaiIjIAZqICMgEXNBEHciESAgaiIgIB9zQRR3Ih9qIiMgEXNBGHci\
ESAgaiIgIB9zQRl3Ih9qIiQgF2ogJCAhIAtqIBkgDHNBGXciDGoiGSAEaiAZIBpzQRB3IhkgFiAYai\
IWaiIYIAxzQRR3IgxqIhogGXNBGHciGXNBEHciISAcIA1qIBYgE3NBGXciE2oiFiAVaiAWIBJzQRB3\
IhIgHWoiFiATc0EUdyITaiIcIBJzQRh3IhIgFmoiFmoiHSAfc0EUdyIfaiIkIA5qIBogCWogIiAbc0\
EYdyIaIB5qIhsgFHNBGXciFGoiHiALaiAeIBJzQRB3IhIgIGoiHiAUc0EUdyIUaiIgIBJzQRh3IhIg\
HmoiHiAUc0EZdyIUaiIiIARqICIgIyAQaiAWIBNzQRl3IhNqIhYgFWogFiAac0EQdyIWIBkgGGoiGG\
oiGSATc0EUdyITaiIaIBZzQRh3IhZzQRB3IiIgHCABaiAYIAxzQRl3IgxqIhggB2ogGCARc0EQdyIR\
IBtqIhggDHNBFHciDGoiGyARc0EYdyIRIBhqIhhqIhwgFHNBFHciFGoiIyAJaiAaIAZqICQgIXNBGH\
ciGiAdaiIdIB9zQRl3Ih9qIiEgCGogISARc0EQdyIRIB5qIh4gH3NBFHciH2oiISARc0EYdyIRIB5q\
Ih4gH3NBGXciH2oiJCAQaiAkICAgDWogGCAMc0EZdyIMaiIYIAVqIBggGnNBEHciGCAWIBlqIhZqIh\
kgDHNBFHciDGoiGiAYc0EYdyIYc0EQdyIgIBsgCmogFiATc0EZdyITaiIWIAJqIBYgEnNBEHciEiAd\
aiIWIBNzQRR3IhNqIhsgEnNBGHciEiAWaiIWaiIdIB9zQRR3Ih9qIiQgF2ogGiALaiAjICJzQRh3Ih\
ogHGoiHCAUc0EZdyIUaiIiIA1qICIgEnNBEHciEiAeaiIeIBRzQRR3IhRqIiIgEnNBGHciEiAeaiIe\
IBRzQRl3IhRqIiMgBWogIyAhIAFqIBYgE3NBGXciE2oiFiACaiAWIBpzQRB3IhYgGCAZaiIYaiIZIB\
NzQRR3IhNqIhogFnNBGHciFnNBEHciISAbIBVqIBggDHNBGXciDGoiGCAPaiAYIBFzQRB3IhEgHGoi\
GCAMc0EUdyIMaiIbIBFzQRh3IhEgGGoiGGoiHCAUc0EUdyIUaiIjIAtqIBogCGogJCAgc0EYdyIaIB\
1qIh0gH3NBGXciH2oiICAOaiAgIBFzQRB3IhEgHmoiHiAfc0EUdyIfaiIgIBFzQRh3IhEgHmoiHiAf\
c0EZdyIfaiIkIAFqICQgIiAKaiAYIAxzQRl3IgxqIhggB2ogGCAac0EQdyIYIBYgGWoiFmoiGSAMc0\
EUdyIMaiIaIBhzQRh3IhhzQRB3IiIgGyAEaiAWIBNzQRl3IhNqIhYgBmogFiASc0EQdyISIB1qIhYg\
E3NBFHciE2oiGyASc0EYdyISIBZqIhZqIh0gH3NBFHciH2oiJCAQaiAaIA1qICMgIXNBGHciGiAcai\
IcIBRzQRl3IhRqIiEgCmogISASc0EQdyISIB5qIh4gFHNBFHciFGoiISASc0EYdyISIB5qIh4gFHNB\
GXciFGoiIyAHaiAjICAgFWogFiATc0EZdyITaiIWIAZqIBYgGnNBEHciFiAYIBlqIhhqIhkgE3NBFH\
ciE2oiGiAWc0EYdyIWc0EQdyIgIBsgAmogGCAMc0EZdyIMaiIYIAlqIBggEXNBEHciESAcaiIYIAxz\
QRR3IgxqIhsgEXNBGHciESAYaiIYaiIcIBRzQRR3IhRqIiMgDWogGiAOaiAkICJzQRh3IhogHWoiHS\
Afc0EZdyIfaiIiIBdqICIgEXNBEHciESAeaiIeIB9zQRR3Ih9qIiIgEXNBGHciESAeaiIeIB9zQRl3\
Ih9qIiQgFWogJCAhIARqIBggDHNBGXciDGoiGCAPaiAYIBpzQRB3IhggFiAZaiIWaiIZIAxzQRR3Ig\
xqIhogGHNBGHciGHNBEHciISAbIAVqIBYgE3NBGXciE2oiFiAIaiAWIBJzQRB3IhIgHWoiFiATc0EU\
dyITaiIbIBJzQRh3IhIgFmoiFmoiHSAfc0EUdyIfaiIkIAFqIBogCmogIyAgc0EYdyIaIBxqIhwgFH\
NBGXciFGoiICAEaiAgIBJzQRB3IhIgHmoiHiAUc0EUdyIUaiIgIBJzQRh3IhIgHmoiHiAUc0EZdyIU\
aiIjIA9qICMgIiACaiAWIBNzQRl3IhNqIhYgCGogFiAac0EQdyIWIBggGWoiGGoiGSATc0EUdyITai\
IaIBZzQRh3IhZzQRB3IiIgGyAGaiAYIAxzQRl3IgxqIhggC2ogGCARc0EQdyIRIBxqIhggDHNBFHci\
DGoiGyARc0EYdyIRIBhqIhhqIhwgFHNBFHciFGoiIyAKaiAaIBdqICQgIXNBGHciCiAdaiIaIB9zQR\
l3Ih1qIh8gEGogHyARc0EQdyIRIB5qIh4gHXNBFHciHWoiHyARc0EYdyIRIB5qIh4gHXNBGXciHWoi\
ISACaiAhICAgBWogGCAMc0EZdyICaiIMIAlqIAwgCnNBEHciCiAWIBlqIgxqIhYgAnNBFHciAmoiGC\
AKc0EYdyIKc0EQdyIZIBsgB2ogDCATc0EZdyIMaiITIA5qIBMgEnNBEHciEiAaaiITIAxzQRR3Igxq\
IhogEnNBGHciEiATaiITaiIbIB1zQRR3Ih1qIiAgFWogGCAEaiAjICJzQRh3IgQgHGoiFSAUc0EZdy\
IUaiIYIAVqIBggEnNBEHciBSAeaiISIBRzQRR3IhRqIhggBXNBGHciBSASaiISIBRzQRl3IhRqIhwg\
CWogHCAfIAZqIBMgDHNBGXciBmoiCSAOaiAJIARzQRB3Ig4gCiAWaiIEaiIJIAZzQRR3IgZqIgogDn\
NBGHciDnNBEHciDCAaIAhqIAQgAnNBGXciCGoiBCANaiAEIBFzQRB3Ig0gFWoiBCAIc0EUdyIIaiIV\
IA1zQRh3Ig0gBGoiBGoiAiAUc0EUdyIRaiITIAxzQRh3IgwgAmoiAiAVIA9qIA4gCWoiDyAGc0EZdy\
IGaiIOIBdqIA4gBXNBEHciBSAgIBlzQRh3Ig4gG2oiF2oiFSAGc0EUdyIGaiIJczYCCCAAIAEgCiAQ\
aiAXIB1zQRl3IhBqIhdqIBcgDXNBEHciASASaiINIBBzQRR3IhBqIhcgAXNBGHciASANaiINIAsgGC\
AHaiAEIAhzQRl3IghqIgdqIAcgDnNBEHciByAPaiIPIAhzQRR3IghqIg5zNgIEIAAgDiAHc0EYdyIH\
IA9qIg8gF3M2AgwgACAJIAVzQRh3IgUgFWoiDiATczYCACAAIAIgEXNBGXcgBXM2AhQgACANIBBzQR\
l3IAdzNgIQIAAgDiAGc0EZdyAMczYCHCAAIA8gCHNBGXcgAXM2AhgL3xkCG38CfiMAQbACayIDJAAC\
QAJAAkACQAJAAkACQAJAAkACQAJAIABB6QBqLQAAQQZ0IAAtAGhqIgRFDQAgACABIAJBgAggBGsiBC\
AEIAJLGyIFEDwaIAIgBWsiAkUNASADQfgAakEQaiAAQRBqIgQpAwA3AwAgA0H4AGpBGGogAEEYaiIG\
KQMANwMAIANB+ABqQSBqIABBIGoiBykDADcDACADQfgAakEwaiAAQTBqKQMANwMAIANB+ABqQThqIA\
BBOGopAwA3AwAgA0H4AGpBwABqIABBwABqKQMANwMAIANB+ABqQcgAaiAAQcgAaikDADcDACADQfgA\
akHQAGogAEHQAGopAwA3AwAgA0H4AGpB2ABqIABB2ABqKQMANwMAIANB+ABqQeAAaiAAQeAAaikDAD\
cDACADIAApAwg3A4ABIAMgACkDKDcDoAEgAEHpAGotAAAhCCAALQBqIQkgAyAALQBoIgo6AOABIAMg\
ACkDACIeNwN4IAMgCSAIRXJBAnIiCDoA4QEgA0HoAWpBGGoiCSAHKQIANwMAIANB6AFqQRBqIgcgBi\
kCADcDACADQegBakEIaiIGIAQpAgA3AwAgAyAAKQIINwPoASADQegBaiADQfgAakEoaiAKIB4gCBAK\
IAkoAgAhCCAHKAIAIQcgBigCACEJIAMoAoQCIQogAygC/AEhCyADKAL0ASEMIAMoAuwBIQ0gAygC6A\
EhDiAAIAApAwAQFyAAQfAOaiIPLQAAIgZBN08NAiAAIAZBBXRqIgRBkAFqIA42AgAgBEGsAWogCjYC\
ACAEQagBaiAINgIAIARBpAFqIAs2AgAgBEGgAWogBzYCACAEQZwBaiAMNgIAIARBmAFqIAk2AgAgBE\
GUAWogDTYCACAPIAZBAWo6AAAgAEEoaiIEQgA3AwAgBEEIakIANwMAIARBEGpCADcDACAEQRhqQgA3\
AwAgBEEgakIANwMAIARBKGpCADcDACAEQTBqQgA3AwAgBEE4akIANwMAIABBADsBaCAAQQhqIgQgAC\
kDcDcDACAEQQhqIABB+ABqKQMANwMAIARBEGogAEGAAWopAwA3AwAgBEEYaiAAQYgBaikDADcDACAA\
IAApAwBCAXw3AwAgASAFaiEBCwJAIAJBgQhJDQAgAEGQAWohDiAAQfAAaiEHIAApAwAhHyADQQhqQS\
hqIQogA0EIakEIaiENIANB+ABqQShqIQkgA0H4AGpBCGohCyAAQfAOaiEMA0AgH0IKhiEeQX8gAkEB\
dmd2QQFqIQUDQCAFIgRBAXYhBSAeIARBf2qtg0IAUg0ACyAEQQp2rSEeAkACQCAEQYAISw0AIAlCAD\
cDACAJQQhqIg9CADcDACAJQRBqIhBCADcDACAJQRhqIhFCADcDACAJQSBqIhJCADcDACAJQShqIhNC\
ADcDACAJQTBqIhRCADcDACAJQThqIhVCADcDACALIAcpAwA3AwAgC0EIaiIFIAdBCGopAwA3AwAgC0\
EQaiIGIAdBEGopAwA3AwAgC0EYaiIIIAdBGGopAwA3AwAgA0EAOwHgASADIB83A3ggAyAALQBqOgDi\
ASADQfgAaiABIAQQPBogDSALKQMANwMAIA1BCGogBSkDADcDACANQRBqIAYpAwA3AwAgDUEYaiAIKQ\
MANwMAIAogCSkDADcDACAKQQhqIA8pAwA3AwAgCkEQaiAQKQMANwMAIApBGGogESkDADcDACAKQSBq\
IBIpAwA3AwAgCkEoaiATKQMANwMAIApBMGogFCkDADcDACAKQThqIBUpAwA3AwAgAy0A4gEhDyADLQ\
DhASEQIAMgAy0A4AEiEToAcCADIAMpA3giHzcDCCADIA8gEEVyQQJyIg86AHEgA0HoAWpBGGoiECAI\
KQIANwMAIANB6AFqQRBqIgggBikCADcDACADQegBakEIaiIGIAUpAgA3AwAgAyALKQIANwPoASADQe\
gBaiAKIBEgHyAPEAogECgCACEPIAgoAgAhCCAGKAIAIRAgAygChAIhESADKAL8ASESIAMoAvQBIRMg\
AygC7AEhFCADKALoASEVIAAgACkDABAXIAwtAAAiBkE3Tw0GIA4gBkEFdGoiBSAVNgIAIAUgETYCHC\
AFIA82AhggBSASNgIUIAUgCDYCECAFIBM2AgwgBSAQNgIIIAUgFDYCBCAMIAZBAWo6AAAMAQsgAiAE\
SQ0GIAAtAGohCCADQfgAakE4akIANwMAIANB+ABqQTBqQgA3AwAgCUIANwMAIANB+ABqQSBqQgA3Aw\
AgA0H4AGpBGGpCADcDACADQfgAakEQakIANwMAIAtCADcDACADQgA3A3ggASAEIAcgHyAIIANB+ABq\
QcAAEA4hBSADQZACakEYakIANwMAIANBkAJqQRBqQgA3AwAgA0GQAmpBCGpCADcDACADQgA3A5ACAk\
AgBUEDSQ0AA0AgBUEFdCIFQcEATw0JIANB+ABqIAUgByAIIANBkAJqQSAQIiIFQQV0IgZBwQBPDQog\
BkEhTw0LIANB+ABqIANBkAJqIAYQlwEaIAVBAksNAAsLIAMoArQBIRYgAygCsAEhFyADKAKsASEYIA\
MoAqgBIRkgAygCpAEhGiADKAKgASEbIAMoApwBIRwgAygCmAEhHSADKAKUASEIIAMoApABIQ8gAygC\
jAEhECADKAKIASERIAMoAoQBIRIgAygCgAEhEyADKAJ8IRQgAygCeCEVIAAgACkDABAXIAwtAAAiBk\
E3Tw0KIA4gBkEFdGoiBSAVNgIAIAUgCDYCHCAFIA82AhggBSAQNgIUIAUgETYCECAFIBI2AgwgBSAT\
NgIIIAUgFDYCBCAMIAZBAWo6AAAgACAAKQMAIB5CAYh8EBcgDC0AACIGQTdPDQsgDiAGQQV0aiIFIB\
02AgAgBSAWNgIcIAUgFzYCGCAFIBg2AhQgBSAZNgIQIAUgGjYCDCAFIBs2AgggBSAcNgIEIAwgBkEB\
ajoAAAsgACAAKQMAIB58Ih83AwAgAiAESQ0LIAEgBGohASACIARrIgJBgAhLDQALCyACRQ0AIAAgAS\
ACEDwaIAAgACkDABAXCyADQbACaiQADwsgA0GQAmpBCGoiBCAJNgIAIANBkAJqQRBqIgUgBzYCACAD\
QZACakEYaiIGIAg2AgAgAyAMNgKcAiADQYEBaiIHIAQpAgA3AAAgAyALNgKkAiADQYkBaiIEIAUpAg\
A3AAAgAyAKNgKsAiADQZEBaiIFIAYpAgA3AAAgAyANNgKUAiADIA42ApACIAMgAykCkAI3AHkgA0EI\
akEYaiAFKQAANwMAIANBCGpBEGogBCkAADcDACADQQhqQQhqIAcpAAA3AwAgAyADKQB5NwMIQdybwA\
BBKyADQQhqQeyLwABBgIvAABB/AAsgA0GYAmoiBCAQNgIAIANBoAJqIgUgCDYCACADQagCaiIGIA82\
AgAgAyATNgKcAiADQfEBaiIHIAQpAwA3AAAgAyASNgKkAiADQfkBaiIIIAUpAwA3AAAgAyARNgKsAi\
ADQYECaiIAIAYpAwA3AAAgAyAUNgKUAiADIBU2ApACIAMgAykDkAI3AOkBIAYgACkAADcDACAFIAgp\
AAA3AwAgBCAHKQAANwMAIAMgAykA6QE3A5ACQdybwABBKyADQZACakHsi8AAQYCLwAAQfwALIAQgAk\
GwisAAEIUBAAsgBUHAAEGMicAAEIUBAAsgBkHAAEGcicAAEIUBAAsgBkEgQayJwAAQhQEACyADQZAC\
akEIaiIEIBM2AgAgA0GQAmpBEGoiBSARNgIAIANBkAJqQRhqIgYgDzYCACADIBI2ApwCIANBgQFqIg\
cgBCkDADcAACADIBA2AqQCIANBiQFqIgQgBSkDADcAACADIAg2AqwCIANBkQFqIgUgBikDADcAACAD\
IBQ2ApQCIAMgFTYCkAIgAyADKQOQAjcAeSADQQhqQRhqIAUpAAA3AwAgA0EIakEQaiAEKQAANwMAIA\
NBCGpBCGogBykAADcDACADIAMpAHk3AwhB3JvAAEErIANBCGpB7IvAAEGAi8AAEH8ACyADQZACakEI\
aiIEIBs2AgAgA0GQAmpBEGoiBSAZNgIAIANBkAJqQRhqIgYgFzYCACADIBo2ApwCIANBgQFqIgcgBC\
kDADcAACADIBg2AqQCIANBiQFqIgQgBSkDADcAACADIBY2AqwCIANBkQFqIgUgBikDADcAACADIBw2\
ApQCIAMgHTYCkAIgAyADKQOQAjcAeSADQQhqQRhqIAUpAAA3AwAgA0EIakEQaiAEKQAANwMAIANBCG\
pBCGogBykAADcDACADIAMpAHk3AwhB3JvAAEErIANBCGpB7IvAAEGAi8AAEH8ACyAEIAJBwIrAABCE\
AQAL9hEBFH8jACECIAAoAgAhAyAAKAIIIQQgACgCDCEFIAAoAgQhBiACQcAAayICQRhqIgdCADcDAC\
ACQSBqIghCADcDACACQThqIglCADcDACACQTBqIgpCADcDACACQShqIgtCADcDACACQQhqIgwgASkA\
CDcDACACQRBqIg0gASkAEDcDACAHIAEoABgiDjYCACAIIAEoACAiBzYCACACIAEpAAA3AwAgAiABKA\
AcIgg2AhwgAiABKAAkIg82AiQgCyABKAAoIhA2AgAgAiABKAAsIgs2AiwgCiABKAAwIhE2AgAgAiAB\
KAA0Igo2AjQgCSABKAA4IhI2AgAgAiABKAA8Igk2AjwgACANKAIAIg0gByARIAIoAgAiEyAPIAogAi\
gCBCIUIAIoAhQiFSAKIA8gFSAUIBEgByANIAYgEyADIAQgBnFqIAUgBkF/c3FqakH4yKq7fWpBB3dq\
IgFqIAYgAigCDCIDaiAEIAwoAgAiDGogBSAUaiABIAZxaiAEIAFBf3NxakHW7p7GfmpBDHcgAWoiAi\
ABcWogBiACQX9zcWpB2+GBoQJqQRF3IAJqIgYgAnFqIAEgBkF/c3FqQe6d9418akEWdyAGaiIBIAZx\
aiACIAFBf3NxakGvn/Crf2pBB3cgAWoiBGogCCABaiAOIAZqIBUgAmogBCABcWogBiAEQX9zcWpBqo\
yfvARqQQx3IARqIgIgBHFqIAEgAkF/c3FqQZOMwcF6akERdyACaiIBIAJxaiAEIAFBf3NxakGBqppq\
akEWdyABaiIGIAFxaiACIAZBf3NxakHYsYLMBmpBB3cgBmoiBGogCyAGaiAQIAFqIA8gAmogBCAGcW\
ogASAEQX9zcWpBr++T2nhqQQx3IARqIgIgBHFqIAYgAkF/c3FqQbG3fWpBEXcgAmoiASACcWogBCAB\
QX9zcWpBvq/zynhqQRZ3IAFqIgYgAXFqIAIgBkF/c3FqQaKiwNwGakEHdyAGaiIEaiASIAFqIAogAm\
ogBCAGcWogASAEQX9zcWpBk+PhbGpBDHcgBGoiAiAEcWogBiACQX9zIgVxakGOh+WzempBEXcgAmoi\
ASAFcWogCSAGaiABIAJxaiAEIAFBf3MiBXFqQaGQ0M0EakEWdyABaiIGIAJxakHiyviwf2pBBXcgBm\
oiBGogCyABaiAEIAZBf3NxaiAOIAJqIAYgBXFqIAQgAXFqQcDmgoJ8akEJdyAEaiICIAZxakHRtPmy\
AmpBDncgAmoiASACQX9zcWogEyAGaiACIARBf3NxaiABIARxakGqj9vNfmpBFHcgAWoiBiACcWpB3a\
C8sX1qQQV3IAZqIgRqIAkgAWogBCAGQX9zcWogECACaiAGIAFBf3NxaiAEIAFxakHTqJASakEJdyAE\
aiICIAZxakGBzYfFfWpBDncgAmoiASACQX9zcWogDSAGaiACIARBf3NxaiABIARxakHI98++fmpBFH\
cgAWoiBiACcWpB5puHjwJqQQV3IAZqIgRqIAMgAWogBCAGQX9zcWogEiACaiAGIAFBf3NxaiAEIAFx\
akHWj9yZfGpBCXcgBGoiAiAGcWpBh5vUpn9qQQ53IAJqIgEgAkF/c3FqIAcgBmogAiAEQX9zcWogAS\
AEcWpB7anoqgRqQRR3IAFqIgYgAnFqQYXSj896akEFdyAGaiIEaiARIAZqIAwgAmogBiABQX9zcWog\
BCABcWpB+Me+Z2pBCXcgBGoiAiAEQX9zcWogCCABaiAEIAZBf3NxaiACIAZxakHZhby7BmpBDncgAm\
oiBiAEcWpBipmp6XhqQRR3IAZqIgQgBnMiBSACc2pBwvJoakEEdyAEaiIBaiALIAZqIAEgBHMgByAC\
aiAFIAFzakGB7ce7eGpBC3cgAWoiAnNqQaLC9ewGakEQdyACaiIGIAJzIBIgBGogAiABcyAGc2pBjP\
CUb2pBF3cgBmoiAXNqQcTU+6V6akEEdyABaiIEaiAIIAZqIAQgAXMgDSACaiABIAZzIARzakGpn/ve\
BGpBC3cgBGoiAnNqQeCW7bV/akEQdyACaiIGIAJzIBAgAWogAiAEcyAGc2pB8Pj+9XtqQRd3IAZqIg\
FzakHG/e3EAmpBBHcgAWoiBGogAyAGaiAEIAFzIBMgAmogASAGcyAEc2pB+s+E1X5qQQt3IARqIgJz\
akGF4bynfWpBEHcgAmoiBiACcyAOIAFqIAIgBHMgBnNqQYW6oCRqQRd3IAZqIgFzakG5oNPOfWpBBH\
cgAWoiBGogDCABaiARIAJqIAEgBnMgBHNqQeWz7rZ+akELdyAEaiICIARzIAkgBmogBCABcyACc2pB\
+PmJ/QFqQRB3IAJqIgFzakHlrLGlfGpBF3cgAWoiBiACQX9zciABc2pBxMSkoX9qQQZ3IAZqIgRqIB\
UgBmogEiABaiAIIAJqIAQgAUF/c3IgBnNqQZf/q5kEakEKdyAEaiICIAZBf3NyIARzakGnx9DcempB\
D3cgAmoiASAEQX9zciACc2pBucDOZGpBFXcgAWoiBiACQX9zciABc2pBw7PtqgZqQQZ3IAZqIgRqIB\
QgBmogECABaiADIAJqIAQgAUF/c3IgBnNqQZKZs/h4akEKdyAEaiICIAZBf3NyIARzakH96L9/akEP\
dyACaiIBIARBf3NyIAJzakHRu5GseGpBFXcgAWoiBiACQX9zciABc2pBz/yh/QZqQQZ3IAZqIgRqIA\
ogBmogDiABaiAJIAJqIAQgAUF/c3IgBnNqQeDNs3FqQQp3IARqIgIgBkF/c3IgBHNqQZSGhZh6akEP\
dyACaiIBIARBf3NyIAJzakGho6DwBGpBFXcgAWoiBiACQX9zciABc2pBgv3Nun9qQQZ3IAZqIgQgAC\
gCAGo2AgAgACALIAJqIAQgAUF/c3IgBnNqQbXk6+l7akEKdyAEaiICIAAoAgxqNgIMIAAgDCABaiAC\
IAZBf3NyIARzakG7pd/WAmpBD3cgAmoiASAAKAIIajYCCCAAIAEgACgCBGogDyAGaiABIARBf3NyIA\
JzakGRp5vcfmpBFXdqNgIEC5gQAQV/IAAgAS0AACICOgAQIAAgAS0AASIDOgARIAAgAS0AAiIEOgAS\
IAAgAS0AAyIFOgATIAAgAS0ABCIGOgAUIAAgAiAALQAAczoAICAAIAMgAC0AAXM6ACEgACAEIAAtAA\
JzOgAiIAAgBSAALQADczoAIyAAIAYgAC0ABHM6ACQgACABLQAFIgI6ABUgACABLQAGIgM6ABYgACAB\
LQAHIgQ6ABcgACABLQAIIgU6ABggACABLQAJIgY6ABkgACACIAAtAAVzOgAlIAAgAyAALQAGczoAJi\
AAIAQgAC0AB3M6ACcgACAFIAAtAAhzOgAoIAAgAS0ACiICOgAaIAAgAS0ACyIDOgAbIAAgAS0ADCIE\
OgAcIAAgAS0ADSIFOgAdIAAgBiAALQAJczoAKSAAIAIgAC0ACnM6ACogACADIAAtAAtzOgArIAAgBC\
AALQAMczoALCAAIAUgAC0ADXM6AC0gACABLQAOIgI6AB4gACACIAAtAA5zOgAuIAAgAS0ADyICOgAf\
IAAgAiAALQAPczoAL0EAIQJBACEDA0AgACADaiIEIAQtAAAgAkH/AXFBqJjAAGotAABzIgI6AAAgA0\
EBaiIDQTBHDQALQQAhAwNAIAAgA2oiBCAELQAAIAJB/wFxQaiYwABqLQAAcyICOgAAIANBAWoiA0Ew\
Rw0ACyACQQFqIQNBACECA0AgACACaiIEIAQtAAAgA0H/AXFBqJjAAGotAABzIgM6AAAgAkEBaiICQT\
BHDQALIANBAmohA0EAIQIDQCAAIAJqIgQgBC0AACADQf8BcUGomMAAai0AAHMiAzoAACACQQFqIgJB\
MEcNAAsgA0EDaiEDQQAhAgNAIAAgAmoiBCAELQAAIANB/wFxQaiYwABqLQAAcyIDOgAAIAJBAWoiAk\
EwRw0ACyADQQRqIQNBACECA0AgACACaiIEIAQtAAAgA0H/AXFBqJjAAGotAABzIgM6AAAgAkEBaiIC\
QTBHDQALIANBBWohA0EAIQIDQCAAIAJqIgQgBC0AACADQf8BcUGomMAAai0AAHMiAzoAACACQQFqIg\
JBMEcNAAsgA0EGaiEDQQAhAgNAIAAgAmoiBCAELQAAIANB/wFxQaiYwABqLQAAcyIDOgAAIAJBAWoi\
AkEwRw0ACyADQQdqIQNBACECA0AgACACaiIEIAQtAAAgA0H/AXFBqJjAAGotAABzIgM6AAAgAkEBai\
ICQTBHDQALIANBCGohA0EAIQIDQCAAIAJqIgQgBC0AACADQf8BcUGomMAAai0AAHMiAzoAACACQQFq\
IgJBMEcNAAsgA0EJaiEDQQAhAgNAIAAgAmoiBCAELQAAIANB/wFxQaiYwABqLQAAcyIDOgAAIAJBAW\
oiAkEwRw0ACyADQQpqIQNBACECA0AgACACaiIEIAQtAAAgA0H/AXFBqJjAAGotAABzIgM6AAAgAkEB\
aiICQTBHDQALIANBC2ohA0EAIQIDQCAAIAJqIgQgBC0AACADQf8BcUGomMAAai0AAHMiAzoAACACQQ\
FqIgJBMEcNAAsgA0EMaiEDQQAhAgNAIAAgAmoiBCAELQAAIANB/wFxQaiYwABqLQAAcyIDOgAAIAJB\
AWoiAkEwRw0ACyADQQ1qIQNBACECA0AgACACaiIEIAQtAAAgA0H/AXFBqJjAAGotAABzIgM6AAAgAk\
EBaiICQTBHDQALIANBDmohA0EAIQIDQCAAIAJqIgQgBC0AACADQf8BcUGomMAAai0AAHMiAzoAACAC\
QQFqIgJBMEcNAAsgA0EPaiEDQQAhAgNAIAAgAmoiBCAELQAAIANB/wFxQaiYwABqLQAAcyIDOgAAIA\
JBAWoiAkEwRw0ACyADQRBqIQNBACECA0AgACACaiIEIAQtAAAgA0H/AXFBqJjAAGotAABzIgM6AAAg\
AkEBaiICQTBHDQALIAAgAC0AMCABLQAAIABBP2oiAi0AAHNBqJjAAGotAABzIgM6ADAgAEExaiIEIA\
QtAAAgAS0AASADc0H/AXFBqJjAAGotAABzIgM6AAAgAEEyaiIEIAQtAAAgAS0AAiADc0H/AXFBqJjA\
AGotAABzIgM6AAAgAEEzaiIEIAQtAAAgAS0AAyADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE0aiIEIA\
QtAAAgAS0ABCADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE1aiIEIAQtAAAgAS0ABSADc0H/AXFBqJjA\
AGotAABzIgM6AAAgAEE2aiIEIAQtAAAgAS0ABiADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE3aiIEIA\
QtAAAgAS0AByADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE4aiIEIAQtAAAgAS0ACCADc0H/AXFBqJjA\
AGotAABzIgM6AAAgAEE5aiIEIAQtAAAgAS0ACSADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE6aiIEIA\
QtAAAgAS0ACiADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE7aiIEIAQtAAAgAS0ACyADc0H/AXFBqJjA\
AGotAABzIgM6AAAgAEE8aiIEIAQtAAAgAS0ADCADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE9aiIEIA\
QtAAAgAS0ADSADc0H/AXFBqJjAAGotAABzIgM6AAAgAEE+aiIAIAAtAAAgAS0ADiADc0H/AXFBqJjA\
AGotAABzIgA6AAAgAiACLQAAIAEtAA8gAHNB/wFxQaiYwABqLQAAczoAAAvJDgIOfwF+IwBBoAJrIg\
ckAAJAAkACQAJAAkACQAJAIAFBgAhLDQAgB0IANwOIAUEAIQgCQCABQYB4cSIJRQ0AQQAgCWshCkEB\
IQsgACEMA0AgC0EBcUUNBEEBIQggB0EBOgCMASAHIAw2AogBIAxBgAhqIQxBACELIApBgAhqIgoNAA\
sLIAFB/wdxIQsCQCAGQQV2IgwgCUEARyIKIAogDEsbRQ0AIAcoAogBIQwgB0EIakEYaiIKIAJBGGop\
AgA3AwAgB0EIakEQaiIIIAJBEGopAgA3AwAgB0EIakEIaiIBIAJBCGopAgA3AwAgByACKQIANwMIIA\
dBCGogDEHAACADIARBAXIQCiAHQQhqIAxBwABqQcAAIAMgBBAKIAdBCGogDEGAAWpBwAAgAyAEEAog\
B0EIaiAMQcABakHAACADIAQQCiAHQQhqIAxBgAJqQcAAIAMgBBAKIAdBCGogDEHAAmpBwAAgAyAEEA\
ogB0EIaiAMQYADakHAACADIAQQCiAHQQhqIAxBwANqQcAAIAMgBBAKIAdBCGogDEGABGpBwAAgAyAE\
EAogB0EIaiAMQcAEakHAACADIAQQCiAHQQhqIAxBgAVqQcAAIAMgBBAKIAdBCGogDEHABWpBwAAgAy\
AEEAogB0EIaiAMQYAGakHAACADIAQQCiAHQQhqIAxBwAZqQcAAIAMgBBAKIAdBCGogDEGAB2pBwAAg\
AyAEEAogB0EIaiAMQcAHakHAACADIARBAnIQCiAFIAopAwA3ABggBSAIKQMANwAQIAUgASkDADcACC\
AFIAcpAwg3AAAgBy0AjAEhCAsgCEH/AXEhDAJAIAsNACAMQQBHIQwMAgsgB0GQAWpBMGoiDUIANwMA\
IAdBkAFqQThqIg5CADcDACAHQZABakHAAGoiD0IANwMAIAdBkAFqQcgAaiIQQgA3AwAgB0GQAWpB0A\
BqIhFCADcDACAHQZABakHYAGoiEkIANwMAIAdBkAFqQeAAaiITQgA3AwAgB0GQAWpBIGoiCiACQRhq\
KQIANwMAIAdBkAFqQRhqIgEgAkEQaikCADcDACAHQZABakEQaiIUIAJBCGopAgA3AwAgB0IANwO4AS\
AHIAQ6APoBIAcgAikCADcDmAEgB0EAOwH4ASAHIAxBAEciDK0gA3w3A5ABIAdBkAFqIAAgCWogCxA8\
GiAHQQhqQRBqIBQpAwA3AwAgB0EIakEYaiABKQMANwMAIAdBCGpBIGogCikDADcDACAHQQhqQTBqIA\
0pAwA3AwAgB0EIakE4aiAOKQMANwMAIAdBCGpBwABqIA8pAwA3AwAgB0EIakHIAGogECkDADcDACAH\
QQhqQdAAaiARKQMANwMAIAdBCGpB2ABqIBIpAwA3AwAgB0EIakHgAGogEykDADcDACAHIAcpA5gBNw\
MQIAcgBykDuAE3AzAgBy0A+gEhCyAHLQD5ASEEIAcgBy0A+AEiAjoAcCAHIAcpA5ABIgM3AwggByAL\
IARFckECciILOgBxIAdBgAJqQRhqIgQgCikDADcDACAHQYACakEQaiIKIAEpAwA3AwAgB0GAAmpBCG\
oiASAUKQMANwMAIAcgBykDmAE3A4ACIAdBgAJqIAdBMGogAiADIAsQCiAMQQV0IgxBIGoiCyAGSw0D\
IAQoAgAhCyAKKAIAIQogASgCACEEIAcoApQCIQIgBygCjAIhASAHKAKEAiEAIAcoAoACIQYgBSAMai\
IMIAcoApwCNgAcIAwgCzYAGCAMIAI2ABQgDCAKNgAQIAwgATYADCAMIAQ2AAggDCAANgAEIAwgBjYA\
AEECQQEgCEH/AXEbIQwMAQtBfyABQX9qQQt2IgxndkEKdEGACGpBgAggDBsiDCABSw0DIAdBCGpBAE\
GAARCdARogASAMayELIAAgDGohCiAMQQp2rSADfCEVAkACQCAMQYAIRw0AIAdBCGpBIGohCEHgACEB\
IABBgAggAiADIAQgB0EIakEgEA4hDAwBC0HAACEBIAdBCGpBwABqIQggACAMIAIgAyAEIAdBCGpBwA\
AQDiEMCyAKIAsgAiAVIAQgCCABEA4hCwJAIAxBAUcNACAGQT9NDQUgBSAHKQAINwAAIAVBOGogB0EI\
akE4aikAADcAACAFQTBqIAdBCGpBMGopAAA3AAAgBUEoaiAHQQhqQShqKQAANwAAIAVBIGogB0EIak\
EgaikAADcAACAFQRhqIAdBCGpBGGopAAA3AAAgBUEQaiAHQQhqQRBqKQAANwAAIAVBCGogB0EIakEI\
aikAADcAAEECIQwMAQsgCyAMakEFdCIMQYEBTw0FIAdBCGogDCACIAQgBSAGECIhDAsgB0GgAmokAC\
AMDwsgByAMNgIIQdybwABBKyAHQQhqQfCKwABBgIvAABB/AAsgCyAGQeyIwAAQhQEAC0G8icAAQSNB\
4InAABCUAQALQcAAIAZB8InAABCFAQALIAxBgAFBgIrAABCFAQALlQwBGH8jACECIAAoAgAhAyAAKA\
IIIQQgACgCDCEFIAAoAgQhBiACQcAAayICQRhqIgdCADcDACACQSBqIghCADcDACACQThqIglCADcD\
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\
eHEgAUcNACAEIQIMAwsgAUEAQRkgAkEBdmtBH3EgAkEfRht0IQMCQANAIAQgA0EddkEEcWpBEGoiBS\
gCACICRQ0BIANBAXQhAyACIQQgAigCBEF4cSABRg0EDAALCyAFIAA2AgAgAEEYaiAENgIACyAAIAA2\
AgwgACAANgIICw8LIAIoAggiASAANgIMIAIgADYCCCAAQRhqQQA2AgAgACACNgIMIAAgATYCCA8LQQ\
AgADYClKdAQQBBACgCjKdAIAFqIgE2AoynQCAAIAFBAXI2AgQgACABaiABNgIAC84LAhB/BH4jAEHg\
AWsiAiQAAkACQAJAAkAgAUHwDmotAAAiAw0AIAJBEGogAUEQaikDADcDACACQRhqIAFBGGopAwA3Aw\
AgAkEgaiABQSBqKQMANwMAIAJBMGogAUEwaikDADcDACACQThqIAFBOGopAwA3AwAgAkHAAGogAUHA\
AGopAwA3AwAgAkHIAGogAUHIAGopAwA3AwAgAkHQAGogAUHQAGopAwA3AwAgAkHYAGogAUHYAGopAw\
A3AwAgAkHgAGogAUHgAGopAwA3AwAgAiABKQMINwMIIAIgASkDKDcDKCABQekAai0AACEEIAEtAGoh\
BSACIAEtAGgiBjoAaCACIAEpAwA3AwAgAiAFIARFckECciIHOgBpDAELIAFBkAFqIQgCQAJAAkAgAU\
HpAGotAAAiBEEGdEEAIAEtAGgiB2tGDQAgAkHwAGpBEGogAUEQaikDADcDACACQfAAakEYaiABQRhq\
KQMANwMAIAJB8ABqQSBqIAFBIGopAwA3AwAgAkHwAGpBMGogAUEwaikDADcDACACQfAAakE4aiABQT\
hqKQMANwMAIAJB8ABqQcAAaiABQcAAaikDADcDACACQfAAakHIAGogAUHIAGopAwA3AwAgAkHwAGpB\
0ABqIAFB0ABqKQMANwMAIAJB8ABqQdgAaiABQdgAaikDADcDACACQfAAakHgAGogAUHgAGopAwA3Aw\
AgAiABKQMINwN4IAIgASkDKDcDmAEgAiABLQBqIgUgBEVyQQJyIgk6ANkBIAIgBzoA2AEgAiABKQMA\
IhI3A3AgBUEEciEKIAJB+ABqIQQgAyEFDAELIANBfmohBSADQQJJDQMgAkHwAGpBEGogAUH4AGopAw\
A3AwAgAkHwAGpBGGogAUGAAWopAwA3AwAgAkGQAWogAUGIAWopAwA3AwAgAkGgAWogCCAFQQV0aiIE\
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\
OmpCADcBACACQcIAakEAOwEAIAJBMGpBFGpCADcCACACQTBqQRxqQgA3AgAgAkEwakEkakIANwIAIA\
JBMGpBLGpCADcCACACQQA7ATQgAkEwNgIwIAJBADYBNiACQegAakEwaiACQTBqQTBqKAIANgIAIAJB\
6ABqQShqIAJBMGpBKGopAwA3AwAgAkHoAGpBIGogAkEwakEgaikDADcDACACQegAakEYaiACQTBqQR\
hqKQMANwMAIAJB6ABqQRBqIAJBMGpBEGopAwA3AwAgAkHoAGpBCGogAkEwakEIaikDADcDACACIAIp\
AzA3A2ggAkEoaiIDIAJB6ABqQSxqKQIANwMAIAJBIGoiBCACQegAakEkaikCADcDACACQRhqIgUgAk\
HoAGpBHGopAgA3AwAgAkEQaiIGIAJB6ABqQRRqKQIANwMAIAJBCGoiByACQfQAaikCADcDACACIAIp\
Amw3AwAgASACEB0gAUIANwMIIAFCADcDACABQQA2AlAgAUEAKQOYnUAiCTcDECABQRhqQQApA6CdQC\
IKNwMAIAFBIGpBACkDqJ1AIgs3AwAgAUEoakEAKQOwnUAiDDcDACABQTBqQQApA7idQCINNwMAIAFB\
OGpBACkDwJ1AIg43AwAgAUHAAGpBACkDyJ1AIg83AwAgAUHIAGpBACkD0J1AIhA3AwACQEEwEAkiCA\
0AQTBBAUEAKALMp0AiAkECIAIbEQQAAAsgCCACKQMANwAAIAhBKGogAykDADcAACAIQSBqIAQpAwA3\
AAAgCEEYaiAFKQMANwAAIAhBEGogBikDADcAACAIQQhqIAcpAwA3AAAgAUIANwMIIAFCADcDACABQQ\
A2AlAgAUEQaiIBIAk3AwAgAUEIaiAKNwMAIAFBEGogCzcDACABQRhqIAw3AwAgAUEgaiANNwMAIAFB\
KGogDjcDACABQTBqIA83AwAgAUE4aiAQNwMAIABBMDYCBCAAIAg2AgAgAkGgAWokAAuOBgIJfwh+Iw\
BB0AFrIgIkACACQcoAakIANwEAIAJB0gBqQQA7AQAgAkHAAGpBFGpCADcCACACQcAAakEcakIANwIA\
IAJBwABqQSRqQgA3AgAgAkHAAGpBLGpCADcCACACQcAAakE0akIANwIAIAJBwABqQTxqQQA6AAAgAk\
H9AGpBADYAACACQYEBakEAOwAAIAJBgwFqQQA6AAAgAkHAADYCQCACQQA7AUQgAkEANgFGIAJBiAFq\
IAJBwABqQcQAEJcBGiACQThqIgMgAkGIAWpBPGopAgA3AwAgAkEwaiIEIAJBiAFqQTRqKQIANwMAIA\
JBKGoiBSACQYgBakEsaikCADcDACACQSBqIgYgAkGIAWpBJGopAgA3AwAgAkEYaiIHIAJBiAFqQRxq\
KQIANwMAIAJBEGoiCCACQYgBakEUaikCADcDACACQQhqIgkgAkGUAWopAgA3AwAgAiACKQKMATcDAC\
ABIAIQFiABQgA3AwggAUIANwMAIAFBADYCUCABQQApA9idQCILNwMQIAFBGGpBACkD4J1AIgw3AwAg\
AUEgakEAKQPonUAiDTcDACABQShqQQApA/CdQCIONwMAIAFBMGpBACkD+J1AIg83AwAgAUE4akEAKQ\
OAnkAiEDcDACABQcAAakEAKQOInkAiETcDACABQcgAakEAKQOQnkAiEjcDAAJAQcAAEAkiCg0AQcAA\
QQFBACgCzKdAIgJBAiACGxEEAAALIAogAikDADcAACAKQThqIAMpAwA3AAAgCkEwaiAEKQMANwAAIA\
pBKGogBSkDADcAACAKQSBqIAYpAwA3AAAgCkEYaiAHKQMANwAAIApBEGogCCkDADcAACAKQQhqIAkp\
AwA3AAAgAUIANwMIIAFCADcDACABQQA2AlAgAUEQaiIBIAs3AwAgAUEIaiAMNwMAIAFBEGogDTcDAC\
ABQRhqIA43AwAgAUEgaiAPNwMAIAFBKGogEDcDACABQTBqIBE3AwAgAUE4aiASNwMAIABBwAA2AgQg\
ACAKNgIAIAJB0AFqJAALzAUBCX8jAEEwayIDJAAgA0EkaiABNgIAIANBAzoAKCADQoCAgICABDcDCC\
ADIAA2AiBBACEEIANBADYCGCADQQA2AhACQAJAAkACQCACKAIIIgVFDQAgAigCACEGIAIoAgQiByAC\
QQxqKAIAIgggCCAHSxsiCUUNASAAIAYoAgAgBigCBCABKAIMEQcADQIgBkEIaiEAIAIoAhAhCiAJIQ\
gDQCADIAVBHGotAAA6ACggAyAFQQRqKQIAQiCJNwMIIAVBGGooAgAhAkEAIQRBACEBAkACQAJAIAVB\
FGooAgAOAwEAAgELIAJBA3QhC0EAIQEgCiALaiILKAIEQQNHDQEgCygCACgCACECC0EBIQELIAMgAj\
YCFCADIAE2AhAgBUEQaigCACECAkACQAJAIAVBDGooAgAOAwEAAgELIAJBA3QhASAKIAFqIgEoAgRB\
A0cNASABKAIAKAIAIQILQQEhBAsgAyACNgIcIAMgBDYCGCAKIAUoAgBBA3RqIgIoAgAgA0EIaiACKA\
IEEQUADQMCQCAIQX9qIggNACAJIQQMAwsgBUEgaiEFIABBBGohAiAAKAIAIQEgAEEIaiEAIAMoAiAg\
ASACKAIAIAMoAiQoAgwRBwBFDQAMAwsLIAIoAgAhBiACKAIEIgcgAkEUaigCACIFIAUgB0sbIghFDQ\
AgAigCECEEIAAgBigCACAGKAIEIAEoAgwRBwANAUEAIQUgCCECA0AgBCAFaiIAKAIAIANBCGogAEEE\
aigCABEFAA0CAkAgAkF/aiICDQAgCCEEDAILIAYgBWohACAFQQhqIQUgAygCICAAQQhqKAIAIABBDG\
ooAgAgAygCJCgCDBEHAEUNAAwCCwsCQCAHIARNDQAgAygCICAGIARBA3RqIgUoAgAgBSgCBCADKAIk\
KAIMEQcADQELQQAhBQwBC0EBIQULIANBMGokACAFC4EFAQF+IAAQMSABIAApAxAiAkI4hiACQiiGQo\
CAgICAgMD/AIOEIAJCGIZCgICAgIDgP4MgAkIIhkKAgICA8B+DhIQgAkIIiEKAgID4D4MgAkIYiEKA\
gPwHg4QgAkIoiEKA/gODIAJCOIiEhIQ3AAAgASAAQRhqKQMAIgJCOIYgAkIohkKAgICAgIDA/wCDhC\
ACQhiGQoCAgICA4D+DIAJCCIZCgICAgPAfg4SEIAJCCIhCgICA+A+DIAJCGIhCgID8B4OEIAJCKIhC\
gP4DgyACQjiIhISENwAIIAEgAEEgaikDACICQjiGIAJCKIZCgICAgICAwP8Ag4QgAkIYhkKAgICAgO\
A/gyACQgiGQoCAgIDwH4OEhCACQgiIQoCAgPgPgyACQhiIQoCA/AeDhCACQiiIQoD+A4MgAkI4iISE\
hDcAECABIABBKGopAwAiAkI4hiACQiiGQoCAgICAgMD/AIOEIAJCGIZCgICAgIDgP4MgAkIIhkKAgI\
CA8B+DhIQgAkIIiEKAgID4D4MgAkIYiEKAgPwHg4QgAkIoiEKA/gODIAJCOIiEhIQ3ABggASAAQTBq\
KQMAIgJCOIYgAkIohkKAgICAgIDA/wCDhCACQhiGQoCAgICA4D+DIAJCCIZCgICAgPAfg4SEIAJCCI\
hCgICA+A+DIAJCGIhCgID8B4OEIAJCKIhCgP4DgyACQjiIhISENwAgIAEgAEE4aikDACICQjiGIAJC\
KIZCgICAgICAwP8Ag4QgAkIYhkKAgICAgOA/gyACQgiGQoCAgIDwH4OEhCACQgiIQoCAgPgPgyACQh\
iIQoCA/AeDhCACQiiIQoD+A4MgAkI4iISEhDcAKAvpBAIGfwV+IwBBkAFrIgIkACACQTpqQgA3AQAg\
AkHCAGpBADsBACACQTBqQRRqQgA3AgAgAkEwakEcakIANwIAIAJBMGpBJGpCADcCACACQQA7ATQgAk\
EoNgIwIAJBADYBNiACQeAAakEoaiACQTBqQShqKAIANgIAIAJB4ABqQSBqIAJBMGpBIGopAwA3AwAg\
AkHgAGpBGGogAkEwakEYaikDADcDACACQeAAakEQaiACQTBqQRBqKQMANwMAIAJB4ABqQQhqIAJBMG\
pBCGopAwA3AwAgAiACKQMwNwNgIAJBCGpBIGoiAyACQeAAakEkaikCADcDACACQQhqQRhqIgQgAkHg\
AGpBHGopAgA3AwAgAkEIakEQaiIFIAJB4ABqQRRqKQIANwMAIAJBCGpBCGoiBiACQewAaikCADcDAC\
ACIAIpAmQ3AwggASACQQhqED0gAUIANwMAIAFBADYCMCABQQApA6CbQCIINwMIIAFBEGpBACkDqJtA\
Igk3AwAgAUEYakEAKQOwm0AiCjcDACABQSBqQQApA7ibQCILNwMAIAFBKGpBACkDwJtAIgw3AwACQE\
EoEAkiBw0AQShBAUEAKALMp0AiAkECIAIbEQQAAAsgByACKQMINwAAIAdBIGogAykDADcAACAHQRhq\
IAQpAwA3AAAgB0EQaiAFKQMANwAAIAdBCGogBikDADcAACABQgA3AwAgAUEANgIwIAFBCGoiASAINw\
MAIAFBCGogCTcDACABQRBqIAo3AwAgAUEYaiALNwMAIAFBIGogDDcDACAAQSg2AgQgACAHNgIAIAJB\
kAFqJAAL5QQCCH8BfiMAQYAPayICJAAgAkEIakGIAWogAUGIAWopAwA3AwAgAkEIakGAAWogAUGAAW\
opAwA3AwAgAkEIakH4AGogAUH4AGopAwA3AwAgAkEIakEQaiABQRBqKQMANwMAIAJBCGpBGGogAUEY\
aikDADcDACACQQhqQSBqIAFBIGopAwA3AwAgAkEIakEwaiABQTBqKQMANwMAIAJBCGpBOGogAUE4ai\
kDADcDACACQQhqQcAAaiABQcAAaikDADcDACACQQhqQcgAaiABQcgAaikDADcDACACQQhqQdAAaiAB\
QdAAaikDADcDACACQQhqQdgAaiABQdgAaikDADcDACACQQhqQeAAaiABQeAAaikDADcDACACIAEpA3\
A3A3ggAiABKQMINwMQIAIgASkDKDcDMCABKQMAIQpBACEDIAJBCGpB8A5qQQA6AAAgAUGQAWohBCAB\
QfAOai0AAEEFdCEFIAJBCGpBkAFqIQYgAS0AaiEHIAEtAGkhCCABLQBoIQkCQANAAkAgBQ0AIAMhAQ\
wCCyAGIAQpAAA3AAAgBkEIaiAEQQhqKQAANwAAIAZBEGogBEEQaikAADcAACAGQRhqIARBGGopAAA3\
AAAgBkEgaiEGIAVBYGohBSAEQSBqIQRBNyEBIANBAWoiA0E3Rw0ACwsgAiAHOgByIAIgCDoAcSACIA\
k6AHAgAiAKNwMIIAIgAToA+A4CQEH4DhAJIgQNAEH4DkEIQQAoAsynQCIEQQIgBBsRBAAACyAEIAJB\
CGpB+A4QlwEhBCAAQfCTwAA2AgQgACAENgIAIAJBgA9qJAALzAQCBH8BfiAAQQhqIQIgACkDACEGAk\
ACQAJAIAAoAhwiA0HAAEcNACACIABBIGpBARAIQQAhAyAAQQA2AhwMAQsgA0E/Sw0BCyAAQRxqIANq\
QQRqQYABOgAAIAAgACgCHCIEQQFqIgM2AhwCQAJAIANBwQBPDQAgAEEgaiIFIANqQQBBPyAEaxCdAR\
oCQEHAACAAKAIca0EHSw0AIAIgBUEBEAggACgCHCIDQcEATw0CIABBIGpBACADEJ0BGgsgAEHYAGog\
BkI7hiAGQiuGQoCAgICAgMD/AIOEIAZCG4ZCgICAgIDgP4MgBkILhkKAgICA8B+DhIQgBkIFiEKAgI\
D4D4MgBkIViEKAgPwHg4QgBkIliEKA/gODIAZCA4ZCOIiEhIQ3AwAgAiAFQQEQCCAAQQA2AhwgASAA\
KAIIIgNBGHQgA0EIdEGAgPwHcXIgA0EIdkGA/gNxIANBGHZycjYAACABIABBDGooAgAiA0EYdCADQQ\
h0QYCA/AdxciADQQh2QYD+A3EgA0EYdnJyNgAEIAEgAEEQaigCACIDQRh0IANBCHRBgID8B3FyIANB\
CHZBgP4DcSADQRh2cnI2AAggASAAQRRqKAIAIgNBGHQgA0EIdEGAgPwHcXIgA0EIdkGA/gNxIANBGH\
ZycjYADCABIABBGGooAgAiAEEYdCAAQQh0QYCA/AdxciAAQQh2QYD+A3EgAEEYdnJyNgAQDwsgA0HA\
AEGonMAAEIQBAAsgA0HAAEG4nMAAEIUBAAsgA0HAAEHInMAAEIcBAAvNBAEFfyMAQfAAayICJAAgAk\
EqakIANwEAIAJBMmpBADsBACACQSBqQRRqQgA3AgAgAkEgakEcakIANwIAIAJBADsBJCACQQA2ASYg\
AkEgNgIgIAJByABqQRhqIAJBIGpBGGopAwA3AwAgAkHIAGpBEGogAkEgakEQaikDADcDACACQcgAak\
EIaiACQSBqQQhqKQMANwMAIAJByABqQSBqIAJBIGpBIGooAgA2AgAgAiACKQMgNwNIIAJBEGogAkHI\
AGpBFGopAgA3AwAgAkEIaiACQdQAaikCADcDACACQRhqIAJByABqQRxqKQIANwMAIAIgAikCTDcDAC\
ACIAEQEiABQgA3AwAgAUEgaiABQYgBaikDADcDACABQRhqIAFBgAFqKQMANwMAIAFBEGogAUH4AGop\
AwA3AwAgASABKQNwNwMIIAFBKGpBAEHCABCdASEDAkAgAUHwDmoiBC0AAEUNACAEQQA6AAALAkBBIB\
AJIgRFDQAgBCACKQMANwAAIARBGGogAkEYaikDADcAACAEQRBqIAJBEGopAwA3AAAgBEEIaiACQQhq\
KQMANwAAIAFCADcDACABQQhqIgVBGGogAUHwAGoiBkEYaikDADcDACAFQRBqIAZBEGopAwA3AwAgBU\
EIaiAGQQhqKQMANwMAIAUgBikDADcDACADQQBBwgAQnQEaAkAgAUHwDmoiAS0AAEUNACABQQA6AAAL\
IABBIDYCBCAAIAQ2AgAgAkHwAGokAA8LQSBBAUEAKALMp0AiAkECIAIbEQQAAAuwBAEJfyMAQTBrIg\
YkAEEAIQcgBkEAOgAIAkACQAJAAkACQCABQUBxIghFDQAgCEFAakEGdkEBaiEJQQAhByAGIQogACEL\
A0AgB0ECRg0CIAogCzYCACAGIAdBAWoiBzoACCAKQQRqIQogC0HAAGohCyAJIAdHDQALCyABQT9xIQ\
wCQCAFQQV2IgsgB0H/////A3EiCiAKIAtLGyILRQ0AIANBBHIhDSALQQV0IQ5BACELIAYhCgNAIAoo\
AgAhByAGQRBqQRhqIgkgAkEYaikCADcDACAGQRBqQRBqIgEgAkEQaikCADcDACAGQRBqQQhqIgMgAk\
EIaikCADcDACAGIAIpAgA3AxAgBkEQaiAHQcAAQgAgDRAKIAQgC2oiB0EYaiAJKQMANwAAIAdBEGog\
ASkDADcAACAHQQhqIAMpAwA3AAAgByAGKQMQNwAAIApBBGohCiAOIAtBIGoiC0cNAAsgBi0ACCEHCw\
JAIAxFDQAgB0EFdCICIAVLDQIgBSACayILQR9NDQMgDEEgRw0EIAQgAmoiAiAAIAhqIgspAAA3AAAg\
AkEYaiALQRhqKQAANwAAIAJBEGogC0EQaikAADcAACACQQhqIAtBCGopAAA3AAAgB0EBaiEHCyAGQT\
BqJAAgBw8LIAYgCzYCEEHcm8AAQSsgBkEQakHci8AAQYCLwAAQfwALIAIgBUH8iMAAEIQBAAtBICAL\
QfyIwAAQhQEAC0EgIAxBmJ7AABCGAQALnwQBB38jAEGgAWsiAiQAIAJBOmpCADcBACACQcIAakEAOw\
EAIAJBMGpBFGpCADcCACACQTBqQRxqQgA3AgAgAkEwakEkakIANwIAIAJBMGpBLGpCADcCACACQQA7\
ATQgAkEwNgIwIAJBADYBNiACQegAakEwaiACQTBqQTBqKAIANgIAIAJB6ABqQShqIAJBMGpBKGopAw\
A3AwAgAkHoAGpBIGogAkEwakEgaikDADcDACACQegAakEYaiACQTBqQRhqKQMANwMAIAJB6ABqQRBq\
IAJBMGpBEGopAwA3AwAgAkHoAGpBCGogAkEwakEIaikDADcDACACIAIpAzA3A2ggAkEoaiIDIAJB6A\
BqQSxqKQIANwMAIAJBIGoiBCACQegAakEkaikCADcDACACQRhqIgUgAkHoAGpBHGopAgA3AwAgAkEQ\
aiIGIAJB6ABqQRRqKQIANwMAIAJBCGoiByACQfQAaikCADcDACACIAIpAmw3AwAgASACEFsgAUEAQc\
gBEJ0BIghBADYCyAECQEEwEAkiAQ0AQTBBAUEAKALMp0AiAkECIAIbEQQAAAsgASACKQMANwAAIAFB\
KGogAykDADcAACABQSBqIAQpAwA3AAAgAUEYaiAFKQMANwAAIAFBEGogBikDADcAACABQQhqIAcpAw\
A3AAAgCEEAQcgBEJ0BQQA2AsgBIABBMDYCBCAAIAE2AgAgAkGgAWokAAufBAEHfyMAQaABayICJAAg\
AkE6akIANwEAIAJBwgBqQQA7AQAgAkEwakEUakIANwIAIAJBMGpBHGpCADcCACACQTBqQSRqQgA3Ag\
AgAkEwakEsakIANwIAIAJBADsBNCACQTA2AjAgAkEANgE2IAJB6ABqQTBqIAJBMGpBMGooAgA2AgAg\
AkHoAGpBKGogAkEwakEoaikDADcDACACQegAakEgaiACQTBqQSBqKQMANwMAIAJB6ABqQRhqIAJBMG\
pBGGopAwA3AwAgAkHoAGpBEGogAkEwakEQaikDADcDACACQegAakEIaiACQTBqQQhqKQMANwMAIAIg\
AikDMDcDaCACQShqIgMgAkHoAGpBLGopAgA3AwAgAkEgaiIEIAJB6ABqQSRqKQIANwMAIAJBGGoiBS\
ACQegAakEcaikCADcDACACQRBqIgYgAkHoAGpBFGopAgA3AwAgAkEIaiIHIAJB9ABqKQIANwMAIAIg\
AikCbDcDACABIAIQXCABQQBByAEQnQEiCEEANgLIAQJAQTAQCSIBDQBBMEEBQQAoAsynQCICQQIgAh\
sRBAAACyABIAIpAwA3AAAgAUEoaiADKQMANwAAIAFBIGogBCkDADcAACABQRhqIAUpAwA3AAAgAUEQ\
aiAGKQMANwAAIAFBCGogBykDADcAACAIQQBByAEQnQFBADYCyAEgAEEwNgIEIAAgATYCACACQaABai\
QAC5YEAQd/IwBBoANrIgIkACACQfICakIANwEAIAJB+gJqQQA7AQAgAkHoAmpBFGpCADcCACACQegC\
akEcakIANwIAIAJB6AJqQSRqQgA3AgAgAkHoAmpBLGpCADcCACACQQA7AewCIAJBMDYC6AIgAkEANg\
HuAiACQTBqQTBqIAJB6AJqQTBqKAIANgIAIAJBMGpBKGogAkHoAmpBKGopAwA3AwAgAkEwakEgaiAC\
QegCakEgaikDADcDACACQTBqQRhqIAJB6AJqQRhqKQMANwMAIAJBMGpBEGogAkHoAmpBEGopAwA3Aw\
AgAkEwakEIaiACQegCakEIaikDADcDACACIAIpA+gCNwMwIAJBKGoiAyACQTBqQSxqKQIANwMAIAJB\
IGoiBCACQTBqQSRqKQIANwMAIAJBGGoiBSACQTBqQRxqKQIANwMAIAJBEGoiBiACQTBqQRRqKQIANw\
MAIAJBCGoiByACQTxqKQIANwMAIAIgAikCNDcDACACQTBqIAFBuAIQlwEaIAJBMGogAhBcAkBBMBAJ\
IggNAEEwQQFBACgCzKdAIgJBAiACGxEEAAALIAggAikDADcAACAIQShqIAMpAwA3AAAgCEEgaiAEKQ\
MANwAAIAhBGGogBSkDADcAACAIQRBqIAYpAwA3AAAgCEEIaiAHKQMANwAAIAEQECAAQTA2AgQgACAI\
NgIAIAJBoANqJAALlgQBB38jAEGgA2siAiQAIAJB8gJqQgA3AQAgAkH6AmpBADsBACACQegCakEUak\
IANwIAIAJB6AJqQRxqQgA3AgAgAkHoAmpBJGpCADcCACACQegCakEsakIANwIAIAJBADsB7AIgAkEw\
NgLoAiACQQA2Ae4CIAJBMGpBMGogAkHoAmpBMGooAgA2AgAgAkEwakEoaiACQegCakEoaikDADcDAC\
ACQTBqQSBqIAJB6AJqQSBqKQMANwMAIAJBMGpBGGogAkHoAmpBGGopAwA3AwAgAkEwakEQaiACQegC\
akEQaikDADcDACACQTBqQQhqIAJB6AJqQQhqKQMANwMAIAIgAikD6AI3AzAgAkEoaiIDIAJBMGpBLG\
opAgA3AwAgAkEgaiIEIAJBMGpBJGopAgA3AwAgAkEYaiIFIAJBMGpBHGopAgA3AwAgAkEQaiIGIAJB\
MGpBFGopAgA3AwAgAkEIaiIHIAJBPGopAgA3AwAgAiACKQI0NwMAIAJBMGogAUG4AhCXARogAkEwai\
ACEFsCQEEwEAkiCA0AQTBBAUEAKALMp0AiAkECIAIbEQQAAAsgCCACKQMANwAAIAhBKGogAykDADcA\
ACAIQSBqIAQpAwA3AAAgCEEYaiAFKQMANwAAIAhBEGogBikDADcAACAIQQhqIAcpAwA3AAAgARAQIA\
BBMDYCBCAAIAg2AgAgAkGgA2okAAuWBAEHfyMAQcACayICJAAgAkGSAmpCADcBACACQZoCakEAOwEA\
IAJBiAJqQRRqQgA3AgAgAkGIAmpBHGpCADcCACACQYgCakEkakIANwIAIAJBiAJqQSxqQgA3AgAgAk\
EAOwGMAiACQTA2AogCIAJBADYBjgIgAkEwakEwaiACQYgCakEwaigCADYCACACQTBqQShqIAJBiAJq\
QShqKQMANwMAIAJBMGpBIGogAkGIAmpBIGopAwA3AwAgAkEwakEYaiACQYgCakEYaikDADcDACACQT\
BqQRBqIAJBiAJqQRBqKQMANwMAIAJBMGpBCGogAkGIAmpBCGopAwA3AwAgAiACKQOIAjcDMCACQShq\
IgMgAkEwakEsaikCADcDACACQSBqIgQgAkEwakEkaikCADcDACACQRhqIgUgAkEwakEcaikCADcDAC\
ACQRBqIgYgAkEwakEUaikCADcDACACQQhqIgcgAkE8aikCADcDACACIAIpAjQ3AwAgAkEwaiABQdgB\
EJcBGiACQTBqIAIQHQJAQTAQCSIIDQBBMEEBQQAoAsynQCICQQIgAhsRBAAACyAIIAIpAwA3AAAgCE\
EoaiADKQMANwAAIAhBIGogBCkDADcAACAIQRhqIAUpAwA3AAAgCEEQaiAGKQMANwAAIAhBCGogBykD\
ADcAACABEBAgAEEwNgIEIAAgCDYCACACQcACaiQAC6sEAQl/IwBB0AFrIgIkACACQcoAakIANwEAIA\
JB0gBqQQA7AQAgAkHAAGpBFGpCADcCACACQcAAakEcakIANwIAIAJBwABqQSRqQgA3AgAgAkHAAGpB\
LGpCADcCACACQcAAakE0akIANwIAIAJBwABqQTxqQQA6AAAgAkH9AGpBADYAACACQYEBakEAOwAAIA\
JBgwFqQQA6AAAgAkHAADYCQCACQQA7AUQgAkEANgFGIAJBiAFqIAJBwABqQcQAEJcBGiACQThqIgMg\
AkGIAWpBPGopAgA3AwAgAkEwaiIEIAJBiAFqQTRqKQIANwMAIAJBKGoiBSACQYgBakEsaikCADcDAC\
ACQSBqIgYgAkGIAWpBJGopAgA3AwAgAkEYaiIHIAJBiAFqQRxqKQIANwMAIAJBEGoiCCACQYgBakEU\
aikCADcDACACQQhqIgkgAkGUAWopAgA3AwAgAiACKQKMATcDACABIAIQSyABQQBByAEQnQEiCkEANg\
LIAQJAQcAAEAkiAQ0AQcAAQQFBACgCzKdAIgJBAiACGxEEAAALIAEgAikDADcAACABQThqIAMpAwA3\
AAAgAUEwaiAEKQMANwAAIAFBKGogBSkDADcAACABQSBqIAYpAwA3AAAgAUEYaiAHKQMANwAAIAFBEG\
ogCCkDADcAACABQQhqIAkpAwA3AAAgCkEAQcgBEJ0BQQA2AsgBIABBwAA2AgQgACABNgIAIAJB0AFq\
JAALqwQBCX8jAEHQAWsiAiQAIAJBygBqQgA3AQAgAkHSAGpBADsBACACQcAAakEUakIANwIAIAJBwA\
BqQRxqQgA3AgAgAkHAAGpBJGpCADcCACACQcAAakEsakIANwIAIAJBwABqQTRqQgA3AgAgAkHAAGpB\
PGpBADoAACACQf0AakEANgAAIAJBgQFqQQA7AAAgAkGDAWpBADoAACACQcAANgJAIAJBADsBRCACQQ\
A2AUYgAkGIAWogAkHAAGpBxAAQlwEaIAJBOGoiAyACQYgBakE8aikCADcDACACQTBqIgQgAkGIAWpB\
NGopAgA3AwAgAkEoaiIFIAJBiAFqQSxqKQIANwMAIAJBIGoiBiACQYgBakEkaikCADcDACACQRhqIg\
cgAkGIAWpBHGopAgA3AwAgAkEQaiIIIAJBiAFqQRRqKQIANwMAIAJBCGoiCSACQZQBaikCADcDACAC\
IAIpAowBNwMAIAEgAhBMIAFBAEHIARCdASIKQQA2AsgBAkBBwAAQCSIBDQBBwABBAUEAKALMp0AiAk\
ECIAIbEQQAAAsgASACKQMANwAAIAFBOGogAykDADcAACABQTBqIAQpAwA3AAAgAUEoaiAFKQMANwAA\
IAFBIGogBikDADcAACABQRhqIAcpAwA3AAAgAUEQaiAIKQMANwAAIAFBCGogCSkDADcAACAKQQBByA\
EQnQFBADYCyAEgAEHAADYCBCAAIAE2AgAgAkHQAWokAAuiBAEJfyMAQaADayICJAAgAkHiAmpCADcB\
ACACQeoCakEAOwEAIAJB2AJqQRRqQgA3AgAgAkHYAmpBHGpCADcCACACQdgCakEkakIANwIAIAJB2A\
JqQSxqQgA3AgAgAkHYAmpBNGpCADcCACACQdgCakE8akEAOgAAIAJBlQNqQQA2AAAgAkGZA2pBADsA\
ACACQZsDakEAOgAAIAJBwAA2AtgCIAJBADsB3AIgAkEANgHeAiACQcAAaiACQdgCakHEABCXARogAk\
E4aiIDIAJBwABqQTxqKQIANwMAIAJBMGoiBCACQcAAakE0aikCADcDACACQShqIgUgAkHAAGpBLGop\
AgA3AwAgAkEgaiIGIAJBwABqQSRqKQIANwMAIAJBGGoiByACQcAAakEcaikCADcDACACQRBqIgggAk\
HAAGpBFGopAgA3AwAgAkEIaiIJIAJBzABqKQIANwMAIAIgAikCRDcDACACQcAAaiABQZgCEJcBGiAC\
QcAAaiACEEsCQEHAABAJIgoNAEHAAEEBQQAoAsynQCICQQIgAhsRBAAACyAKIAIpAwA3AAAgCkE4ai\
ADKQMANwAAIApBMGogBCkDADcAACAKQShqIAUpAwA3AAAgCkEgaiAGKQMANwAAIApBGGogBykDADcA\
ACAKQRBqIAgpAwA3AAAgCkEIaiAJKQMANwAAIAEQECAAQcAANgIEIAAgCjYCACACQaADaiQAC6IEAQ\
l/IwBBoANrIgIkACACQeICakIANwEAIAJB6gJqQQA7AQAgAkHYAmpBFGpCADcCACACQdgCakEcakIA\
NwIAIAJB2AJqQSRqQgA3AgAgAkHYAmpBLGpCADcCACACQdgCakE0akIANwIAIAJB2AJqQTxqQQA6AA\
AgAkGVA2pBADYAACACQZkDakEAOwAAIAJBmwNqQQA6AAAgAkHAADYC2AIgAkEAOwHcAiACQQA2Ad4C\
IAJBwABqIAJB2AJqQcQAEJcBGiACQThqIgMgAkHAAGpBPGopAgA3AwAgAkEwaiIEIAJBwABqQTRqKQ\
IANwMAIAJBKGoiBSACQcAAakEsaikCADcDACACQSBqIgYgAkHAAGpBJGopAgA3AwAgAkEYaiIHIAJB\
wABqQRxqKQIANwMAIAJBEGoiCCACQcAAakEUaikCADcDACACQQhqIgkgAkHMAGopAgA3AwAgAiACKQ\
JENwMAIAJBwABqIAFBmAIQlwEaIAJBwABqIAIQTAJAQcAAEAkiCg0AQcAAQQFBACgCzKdAIgJBAiAC\
GxEEAAALIAogAikDADcAACAKQThqIAMpAwA3AAAgCkEwaiAEKQMANwAAIApBKGogBSkDADcAACAKQS\
BqIAYpAwA3AAAgCkEYaiAHKQMANwAAIApBEGogCCkDADcAACAKQQhqIAkpAwA3AAAgARAQIABBwAA2\
AgQgACAKNgIAIAJBoANqJAALogQBCX8jAEHgAmsiAiQAIAJBogJqQgA3AQAgAkGqAmpBADsBACACQZ\
gCakEUakIANwIAIAJBmAJqQRxqQgA3AgAgAkGYAmpBJGpCADcCACACQZgCakEsakIANwIAIAJBmAJq\
QTRqQgA3AgAgAkGYAmpBPGpBADoAACACQdUCakEANgAAIAJB2QJqQQA7AAAgAkHbAmpBADoAACACQc\
AANgKYAiACQQA7AZwCIAJBADYBngIgAkHAAGogAkGYAmpBxAAQlwEaIAJBOGoiAyACQcAAakE8aikC\
ADcDACACQTBqIgQgAkHAAGpBNGopAgA3AwAgAkEoaiIFIAJBwABqQSxqKQIANwMAIAJBIGoiBiACQc\
AAakEkaikCADcDACACQRhqIgcgAkHAAGpBHGopAgA3AwAgAkEQaiIIIAJBwABqQRRqKQIANwMAIAJB\
CGoiCSACQcwAaikCADcDACACIAIpAkQ3AwAgAkHAAGogAUHYARCXARogAkHAAGogAhAWAkBBwAAQCS\
IKDQBBwABBAUEAKALMp0AiAkECIAIbEQQAAAsgCiACKQMANwAAIApBOGogAykDADcAACAKQTBqIAQp\
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\
CDcAACAGQRhqIAMpAwA3AAAgBkEQaiAEKQMANwAAIAZBCGogBSkDADcAACABEBAgAEEgNgIEIAAgBj\
YCACACQcABaiQAC5ADAQV/IwBB8ABrIgIkACACQSpqQgA3AQAgAkEyakEAOwEAIAJBIGpBFGpCADcC\
ACACQSBqQRxqQgA3AgAgAkEAOwEkIAJBIDYCICACQQA2ASYgAkHIAGpBIGogAkEgakEgaigCADYCAC\
ACQcgAakEYaiACQSBqQRhqKQMANwMAIAJByABqQRBqIAJBIGpBEGopAwA3AwAgAkHIAGpBCGogAkEg\
akEIaikDADcDACACIAIpAyA3A0ggAkEYaiIDIAJByABqQRxqKQIANwMAIAJBEGoiBCACQcgAakEUai\
kCADcDACACQQhqIgUgAkHUAGopAgA3AwAgAiACKQJMNwMAIAEgAhBnIAFBAEHIARCdASIGQQA2AsgB\
AkBBIBAJIgENAEEgQQFBACgCzKdAIgJBAiACGxEEAAALIAEgAikDADcAACABQRhqIAMpAwA3AAAgAU\
EQaiAEKQMANwAAIAFBCGogBSkDADcAACAGQQBByAEQnQFBADYCyAEgAEEgNgIEIAAgATYCACACQfAA\
aiQAC5ADAQV/IwBB8ABrIgIkACACQSpqQgA3AQAgAkEyakEAOwEAIAJBIGpBFGpCADcCACACQSBqQR\
xqQgA3AgAgAkEAOwEkIAJBIDYCICACQQA2ASYgAkHIAGpBIGogAkEgakEgaigCADYCACACQcgAakEY\
aiACQSBqQRhqKQMANwMAIAJByABqQRBqIAJBIGpBEGopAwA3AwAgAkHIAGpBCGogAkEgakEIaikDAD\
cDACACIAIpAyA3A0ggAkEYaiIDIAJByABqQRxqKQIANwMAIAJBEGoiBCACQcgAakEUaikCADcDACAC\
QQhqIgUgAkHUAGopAgA3AwAgAiACKQJMNwMAIAEgAhBpIAFBAEHIARCdASIGQQA2AsgBAkBBIBAJIg\
ENAEEgQQFBACgCzKdAIgJBAiACGxEEAAALIAEgAikDADcAACABQRhqIAMpAwA3AAAgAUEQaiAEKQMA\
NwAAIAFBCGogBSkDADcAACAGQQBByAEQnQFBADYCyAEgAEEgNgIEIAAgATYCACACQfAAaiQAC4gDAQ\
V/IwBBoANrIgIkACACQYIDakIANwEAIAJBigNqQQA7AQAgAkH4AmpBFGpCADcCACACQfgCakEcakIA\
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\
RXIQCiAEQQBBwQAQnQEaIAMgAy0AAEEBajoAAAtBACEDIAJBwQBJDQEgAEEIaiEFIABB6QBqIgMtAA\
AhBANAIAUgAUHAACAAKQMAIAAtAGogBEH/AXFFchAKIAMgAy0AAEEBaiIEOgAAIAFBwABqIQEgAkFA\
aiICQcAASw0ACyAALQBoIQQLIARB/wFxIgNBwQBPDQIgAkHAACADayIEIAQgAksbIQILIAAgA2pBKG\
ogASACEJcBGiAAIAAtAGggAmo6AGggAA8LIANBwABBkIjAABCEAQALIANBwABBkIjAABCEAQALggMC\
BH8BfiAAQQhqIQIgACkDACEGAkACQAJAIAAoAjAiA0HAAEcNACACIABBNGoQBkEAIQMgAEEANgIwDA\
ELIANBP0sNAQsgAEE0aiIEIANqQYABOgAAIAAgACgCMCIFQQFqIgM2AjACQAJAIANBwQBPDQAgAEEw\
aiADakEEakEAQT8gBWsQnQEaAkBBwAAgACgCMGtBB0sNACACIAQQBiAAKAIwIgNBwQBPDQIgAEE0ak\
EAIAMQnQEaCyAAQewAaiAGQgOGNwIAIAIgBBAGIABBADYCMCABIAAoAgg2AAAgASAAQQxqKAIANgAE\
IAEgAEEQaigCADYACCABIABBFGooAgA2AAwgASAAQRhqKAIANgAQIAEgAEEcaigCADYAFCABIABBIG\
ooAgA2ABggASAAQSRqKAIANgAcIAEgAEEoaigCADYAICABIABBLGooAgA2ACQPCyADQcAAQaicwAAQ\
hAEACyADQcAAQbicwAAQhQEACyADQcAAQcicwAAQhwEAC/kCAQV/IwBB4ABrIgIkACACQSpqQgA3AQ\
AgAkEyakEAOwEAIAJBIGpBFGpCADcCACACQSBqQRxqQQA2AgAgAkEcNgIgIAJBADsBJCACQQA2ASYg\
AkHAAGpBGGogAkEgakEYaikDADcDACACQcAAakEQaiACQSBqQRBqKQMANwMAIAJBwABqQQhqIAJBIG\
pBCGopAwA3AwAgAiACKQMgNwNAIAJBGGoiAyACQcAAakEcaigCADYCACACQRBqIgQgAkHAAGpBFGop\
AgA3AwAgAkEIaiIFIAJBzABqKQIANwMAIAIgAikCRDcDACABIAIQZiABQQBByAEQnQEiBkEANgLIAQ\
JAQRwQCSIBDQBBHEEBQQAoAsynQCICQQIgAhsRBAAACyABIAIpAwA3AAAgAUEYaiADKAIANgAAIAFB\
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\
AQALIANBkAFBhKDAABCEAQAL7wIBBX8CQAJAAkACQEHoACAAKALIASIDayIEIAJNDQAgAyACaiIFIA\
NJDQEgBUHpAE8NAiAAQcgBaiADakEEaiABIAIQlwEaIAAgACgCyAEgAmo2AsgBDwsCQAJAIAMNACAB\
IQUMAQsgA0HpAE8NAyACIARrIQIgASAEaiEFIAAgA2pBzAFqIAEgBBCXARpBACEDA0AgACADaiIBIA\
EtAAAgAUHMAWotAABzOgAAIANBAWoiA0HoAEcNAAsgABATCyAFIAIgAkHoAHAiBmsiAmohBwJAIAJB\
6ABJDQADQCAFQegAaiEEIAJBmH9qIQJBACEDA0AgACADaiIBIAEtAAAgBSADai0AAHM6AAAgA0EBai\
IDQegARw0ACyAAEBMgBCEFIAJB6ABPDQALCyAAQcwBaiAHIAYQlwEaIAAgBjYCyAEPCyADIAVB9J/A\
ABCIAQALIAVB6ABB9J/AABCFAQALIANB6ABBhKDAABCEAQAL8QIBBX8jAEGgA2siAiQAIAJBigNqQg\
A3AQAgAkGSA2pBADsBACACQYADakEUakIANwIAIAJBgANqQRxqQQA2AgAgAkEcNgKAAyACQQA7AYQD\
IAJBADYBhgMgAkEgakEYaiACQYADakEYaikDADcDACACQSBqQRBqIAJBgANqQRBqKQMANwMAIAJBIG\
pBCGogAkGAA2pBCGopAwA3AwAgAiACKQOAAzcDICACQRhqIgMgAkEgakEcaigCADYCACACQRBqIgQg\
AkEgakEUaikCADcDACACQQhqIgUgAkEsaikCADcDACACIAIpAiQ3AwAgAkEgaiABQeACEJcBGiACQS\
BqIAIQZgJAQRwQCSIGDQBBHEEBQQAoAsynQCICQQIgAhsRBAAACyAGIAIpAwA3AAAgBkEYaiADKAIA\
NgAAIAZBEGogBCkDADcAACAGQQhqIAUpAwA3AAAgARAQIABBHDYCBCAAIAY2AgAgAkGgA2okAAvxAg\
EFfyMAQaADayICJAAgAkGKA2pCADcBACACQZIDakEAOwEAIAJBgANqQRRqQgA3AgAgAkGAA2pBHGpB\
ADYCACACQRw2AoADIAJBADsBhAMgAkEANgGGAyACQSBqQRhqIAJBgANqQRhqKQMANwMAIAJBIGpBEG\
ogAkGAA2pBEGopAwA3AwAgAkEgakEIaiACQYADakEIaikDADcDACACIAIpA4ADNwMgIAJBGGoiAyAC\
QSBqQRxqKAIANgIAIAJBEGoiBCACQSBqQRRqKQIANwMAIAJBCGoiBSACQSxqKQIANwMAIAIgAikCJD\
cDACACQSBqIAFB4AIQlwEaIAJBIGogAhBoAkBBHBAJIgYNAEEcQQFBACgCzKdAIgJBAiACGxEEAAAL\
IAYgAikDADcAACAGQRhqIAMoAgA2AAAgBkEQaiAEKQMANwAAIAZBCGogBSkDADcAACABEBAgAEEcNg\
IEIAAgBjYCACACQaADaiQAC/ECAQV/IwBBsAFrIgIkACACQZoBakIANwEAIAJBogFqQQA7AQAgAkGQ\
AWpBFGpCADcCACACQZABakEcakEANgIAIAJBHDYCkAEgAkEAOwGUASACQQA2AZYBIAJBIGpBGGogAk\
GQAWpBGGopAwA3AwAgAkEgakEQaiACQZABakEQaikDADcDACACQSBqQQhqIAJBkAFqQQhqKQMANwMA\
IAIgAikDkAE3AyAgAkEYaiIDIAJBIGpBHGooAgA2AgAgAkEQaiIEIAJBIGpBFGopAgA3AwAgAkEIai\
IFIAJBLGopAgA3AwAgAiACKQIkNwMAIAJBIGogAUHwABCXARogAkEgaiACEEACQEEcEAkiBg0AQRxB\
AUEAKALMp0AiAkECIAIbEQQAAAsgBiACKQMANwAAIAZBGGogAygCADYAACAGQRBqIAQpAwA3AAAgBk\
EIaiAFKQMANwAAIAEQECAAQRw2AgQgACAGNgIAIAJBsAFqJAAL0AICBX8BfiMAQTBrIgIkAEEnIQMC\
QAJAIABCkM4AWg0AIAAhBwwBC0EnIQMDQCACQQlqIANqIgRBfGogAEKQzgCAIgdC8LF/fiAAfKciBU\
H//wNxQeQAbiIGQQF0QYqNwABqLwAAOwAAIARBfmogBkGcf2wgBWpB//8DcUEBdEGKjcAAai8AADsA\
ACADQXxqIQMgAEL/wdcvViEEIAchACAEDQALCwJAIAenIgRB4wBMDQAgAkEJaiADQX5qIgNqIAenIg\
VB//8DcUHkAG4iBEGcf2wgBWpB//8DcUEBdEGKjcAAai8AADsAAAsCQAJAIARBCUoNACACQQlqIANB\
f2oiA2ogBEEwajoAAAwBCyACQQlqIANBfmoiA2ogBEEBdEGKjcAAai8AADsAAAsgAUGoosAAQQAgAk\
EJaiADakEnIANrEBkhAyACQTBqJAAgAwviAgIEfwF+IABBzABqIQEgACkDACEFAkACQAJAIAAoAggi\
AkHAAEcNACABIABBDGpBARAEQQAhAiAAQQA2AggMAQsgAkE/Sw0BCyAAQQhqIAJqQQRqQYABOgAAIA\
AgACgCCCIDQQFqIgI2AggCQAJAIAJBwQBPDQAgAEEMaiIEIAJqQQBBPyADaxCdARoCQEHAACAAKAII\
a0EHSw0AIAEgBEEBEAQgACgCCCICQcEATw0CIABBDGpBACACEJ0BGgsgAEHEAGogBUI4hiAFQiiGQo\
CAgICAgMD/AIOEIAVCGIZCgICAgIDgP4MgBUIIhkKAgICA8B+DhIQgBUIIiEKAgID4D4MgBUIYiEKA\
gPwHg4QgBUIoiEKA/gODIAVCOIiEhIQ3AgAgASAEQQEQBCAAQQA2AggPCyACQcAAQaicwAAQhAEACy\
ACQcAAQbicwAAQhQEACyACQcAAQcicwAAQhwEAC7kCAQR/IwBBoAFrIgIkACACQQA2AhAgAkEIaiAC\
QRBqQQRyIAJB1ABqEKgBAkACQCACKAIMIAIoAggiA2siBEHAACAEQcAASRsiBEUNAANAIAMgAS0AAD\
oAACACIAIoAhBBAWoiBTYCECADQQFqIQMgAUEBaiEBIARBf2oiBA0ADAILCyACKAIQIQULAkAgBUE/\
Sw0AIAVBwAAQiQEACyACQdgAaiACQRBqQcQAEJcBGiAAQThqIAJBlAFqKQIANwAAIABBMGogAkGMAW\
opAgA3AAAgAEEoaiACQYQBaikCADcAACAAQSBqIAJB/ABqKQIANwAAIABBGGogAkH0AGopAgA3AAAg\
AEEQaiACQewAaikCADcAACAAQQhqIAJB5ABqKQIANwAAIAAgAikCXDcAACACQaABaiQAC7kCAQN/Iw\
BBEGsiAiQAAkAgACgCyAEiA0HHAEsNACAAIANqQcwBakEGOgAAAkAgA0EBaiIEQcgARg0AIAAgBGpB\
zAFqQQBBxwAgA2sQnQEaC0EAIQMgAEEANgLIASAAQZMCaiIEIAQtAABBgAFyOgAAA0AgACADaiIEIA\
QtAAAgBEHMAWotAABzOgAAIANBAWoiA0HIAEcNAAsgABATIAEgACkAADcAACABQThqIABBOGopAAA3\
AAAgAUEwaiAAQTBqKQAANwAAIAFBKGogAEEoaikAADcAACABQSBqIABBIGopAAA3AAAgAUEYaiAAQR\
hqKQAANwAAIAFBEGogAEEQaikAADcAACABQQhqIABBCGopAAA3AAAgAkEQaiQADwtB9Z7AAEEXIAJB\
CGpBjJ/AAEHEocAAEH8AC7kCAQN/IwBBEGsiAiQAAkAgACgCyAEiA0HHAEsNACAAIANqQcwBakEBOg\
AAAkAgA0EBaiIEQcgARg0AIAAgBGpBzAFqQQBBxwAgA2sQnQEaC0EAIQMgAEEANgLIASAAQZMCaiIE\
IAQtAABBgAFyOgAAA0AgACADaiIEIAQtAAAgBEHMAWotAABzOgAAIANBAWoiA0HIAEcNAAsgABATIA\
EgACkAADcAACABQThqIABBOGopAAA3AAAgAUEwaiAAQTBqKQAANwAAIAFBKGogAEEoaikAADcAACAB\
QSBqIABBIGopAAA3AAAgAUEYaiAAQRhqKQAANwAAIAFBEGogAEEQaikAADcAACABQQhqIABBCGopAA\
A3AAAgAkEQaiQADwtB9Z7AAEEXIAJBCGpBjJ/AAEGEocAAEH8AC8ICAQh/IwBB8ABrIgFBKGoiAkIA\
NwMAIAFBIGoiA0IANwMAIAFBGGoiBEIANwMAIAFBEGoiBUIANwMAIAFBCGoiBkIANwMAIAFCADcDAC\
ABQcoAakIANwEAIAFB0gBqQQA7AQAgAUEQNgJAIAFBADsBRCABQQA2AUYgAUHYAGpBEGogAUHAAGpB\
EGooAgA2AgAgAUHYAGpBCGogAUHAAGpBCGopAwA3AwAgASABKQNANwNYIAFBOGoiByABQeQAaikCAD\
cDACABQTBqIgggASkCXDcDACAAQcwAaiAHKQMANwAAIABBxABqIAgpAwA3AAAgAEE8aiACKQMANwAA\
IABBNGogAykDADcAACAAQSxqIAQpAwA3AAAgAEEkaiAFKQMANwAAIABBHGogBikDADcAACAAIAEpAw\
A3ABQgAEEANgIAC8ECAgR/AX4gAEEIaiECIAApAwAhBgJAAkACQCAAKAIcIgNBwABHDQAgAiAAQSBq\
EAdBACEDIABBADYCHAwBCyADQT9LDQELIABBIGoiBCADakGAAToAACAAIAAoAhwiBUEBaiIDNgIcAk\
ACQCADQcEATw0AIABBHGogA2pBBGpBAEE/IAVrEJ0BGgJAQcAAIAAoAhxrQQdLDQAgAiAEEAcgACgC\
HCIDQcEATw0CIABBIGpBACADEJ0BGgsgAEHYAGogBkIDhjcDACACIAQQByAAQQA2AhwgASAAKAIINg\
AAIAEgAEEMaigCADYABCABIABBEGooAgA2AAggASAAQRRqKAIANgAMIAEgAEEYaigCADYAEA8LIANB\
wABBqJzAABCEAQALIANBwABBuJzAABCFAQALIANBwABByJzAABCHAQALtwICBX8BfiMAQcABayICJA\
AgAkHQAGpBCGoiAyABQRBqKQMANwMAIAJB0ABqQRBqIgQgAUEYaikDADcDACACQdAAakEYaiIFIAFB\
IGopAwA3AwAgAkHQAGpBIGoiBiABQShqKQMANwMAIAIgASkDCDcDUCABKQMAIQcgAkH4AGpBBHIgAU\
E0ahBKIAIgASgCMDYCeCACQQhqIAJB+ABqQcQAEJcBGgJAQfgAEAkiAQ0AQfgAQQhBACgCzKdAIgJB\
AiACGxEEAAALIAEgBzcDACABIAIpA1A3AwggAUEQaiADKQMANwMAIAFBGGogBCkDADcDACABQSBqIA\
UpAwA3AwAgAUEoaiAGKQMANwMAIAFBMGogAkEIakHEABCXARogAEHclMAANgIEIAAgATYCACACQcAB\
aiQAC7gCAgR/AX4gAEHMAGohAiAAKQMAIQYCQAJAAkAgACgCCCIDQcAARw0AIAIgAEEMahAMQQAhAy\
AAQQA2AggMAQsgA0E/Sw0BCyAAQQhqIANqQQRqQYABOgAAIAAgACgCCCIEQQFqIgM2AggCQAJAIANB\
wQBPDQAgAEEMaiIFIANqQQBBPyAEaxCdARoCQEHAACAAKAIIa0EHSw0AIAIgBRAMIAAoAggiA0HBAE\
8NAiAAQQxqQQAgAxCdARoLIABBxABqIAZCA4Y3AgAgAiAFEAwgAEEANgIIIAEgACgCTDYAACABIABB\
0ABqKAIANgAEIAEgAEHUAGooAgA2AAggASAAQdgAaigCADYADA8LIANBwABBqJzAABCEAQALIANBwA\
BBuJzAABCFAQALIANBwABByJzAABCHAQALuAICBH8BfiAAQcwAaiECIAApAwAhBgJAAkACQCAAKAII\
IgNBwABHDQAgAiAAQQxqEA9BACEDIABBADYCCAwBCyADQT9LDQELIABBDGoiBCADakGAAToAACAAIA\
AoAggiBUEBaiIDNgIIAkACQCADQcEATw0AIABBCGogA2pBBGpBAEE/IAVrEJ0BGgJAQcAAIAAoAghr\
QQdLDQAgAiAEEA8gACgCCCIDQcEATw0CIABBDGpBACADEJ0BGgsgAEHEAGogBkIDhjcCACACIAQQDy\
AAQQA2AgggASAAKAJMNgAAIAEgAEHQAGooAgA2AAQgASAAQdQAaigCADYACCABIABB2ABqKAIANgAM\
DwsgA0HAAEGonMAAEIQBAAsgA0HAAEG4nMAAEIUBAAsgA0HAAEHInMAAEIcBAAujAgIEfwJ+IAAgAC\
kDACIHIAKtQgOGfCIINwMAIABBCGoiAyADKQMAIAggB1StfDcDAAJAAkACQAJAQYABIAAoAlAiA2si\
BCACTQ0AIAMgAmoiBCADSQ0BIARBgQFPDQIgAEHQAGogA2pBBGogASACEJcBGiAAIAAoAlAgAmo2Al\
APCyAAQRBqIQUCQCADRQ0AIANBgQFPDQMgAEHUAGoiBiADaiABIAQQlwEaIABBADYCUCAFIAZBARAD\
IAIgBGshAiABIARqIQELIAUgASACQQd2EAMgAEHUAGogASACQYB/cWogAkH/AHEiAhCXARogACACNg\
JQDwsgAyAEQYicwAAQiAEACyAEQYABQYicwAAQhQEACyADQYABQZicwAAQhAEAC54CAQR/IAAgACkD\
ACACrXw3AwACQAJAAkACQEHAACAAKAIIIgNrIgQgAk0NACADIAJqIgUgA0kNASAFQcEATw0CIABBCG\
ogA2pBBGogASACEJcBGiAAIAAoAgggAmo2AggPCyAAQcwAaiEFAkAgA0UNACADQcEATw0DIABBDGoi\
BiADaiABIAQQlwEaIAUgBhAMIAIgBGshAiABIARqIQELIAJBP3EhAyABIAJBQHEiAmohBAJAIAJFDQ\
BBACACayECA0AgBSABEAwgAUHAAGohASACQcAAaiICDQALCyAAQQxqIAQgAxCXARogACADNgIIDwsg\
AyAFQfSfwAAQiAEACyAFQcAAQfSfwAAQhQEACyADQcAAQYSgwAAQhAEAC50CAQR/IAAgACkDACACrX\
w3AwACQAJAAkACQEHAACAAKAIcIgNrIgQgAk0NACADIAJqIgUgA0kNASAFQcEATw0CIABBHGogA2pB\
BGogASACEJcBGiAAIAAoAhwgAmo2AhwPCyAAQQhqIQUCQCADRQ0AIANBwQBPDQMgAEEgaiIGIANqIA\
EgBBCXARogBSAGEAcgAiAEayECIAEgBGohAQsgAkE/cSEDIAEgAkFAcSICaiEEAkAgAkUNAEEAIAJr\
IQIDQCAFIAEQByABQcAAaiEBIAJBwABqIgINAAsLIABBIGogBCADEJcBGiAAIAM2AhwPCyADIAVB9J\
/AABCIAQALIAVBwABB9J/AABCFAQALIANBwABBhKDAABCEAQALngIBBH8gACAAKQMAIAKtfDcDAAJA\
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\
OgAAA0AgACADaiIEIAQtAAAgBEHMAWotAABzOgAAIANBAWoiA0HoAEcNAAsgABATIAEgACkAADcAAC\
ABQShqIABBKGopAAA3AAAgAUEgaiAAQSBqKQAANwAAIAFBGGogAEEYaikAADcAACABQRBqIABBEGop\
AAA3AAAgAUEIaiAAQQhqKQAANwAAIAJBEGokAA8LQfWewABBFyACQQhqQYyfwABB9KDAABB/AAuZAg\
EDfyMAQRBrIgIkAAJAIAAoAsgBIgNB5wBLDQAgACADakHMAWpBBjoAAAJAIANBAWoiBEHoAEYNACAA\
IARqQcwBakEAQecAIANrEJ0BGgtBACEDIABBADYCyAEgAEGzAmoiBCAELQAAQYABcjoAAANAIAAgA2\
oiBCAELQAAIARBzAFqLQAAczoAACADQQFqIgNB6ABHDQALIAAQEyABIAApAAA3AAAgAUEoaiAAQShq\
KQAANwAAIAFBIGogAEEgaikAADcAACABQRhqIABBGGopAAA3AAAgAUEQaiAAQRBqKQAANwAAIAFBCG\
ogAEEIaikAADcAACACQRBqJAAPC0H1nsAAQRcgAkEIakGMn8AAQbShwAAQfwALhQIBBH8CQAJAAkAC\
QEEQIAAoAgAiA2siBCACTQ0AIAMgAmoiBSADSQ0BIAVBEU8NAiAAIANqQQRqIAEgAhCXARogACAAKA\
IAIAJqNgIADwsgAEEUaiEFAkAgA0UNACADQRFPDQMgAEEEaiIGIANqIAEgBBCXARogBSAGEA0gAiAE\
ayECIAEgBGohAQsgAkEPcSEDIAEgAkFwcSICaiEEAkAgAkUNAEEAIAJrIQIDQCAFIAEQDSABQRBqIQ\
EgAkEQaiICDQALCyAAQQRqIAQgAxCXARogACADNgIADwsgAyAFQfSfwAAQiAEACyAFQRBB9J/AABCF\
AQALIANBEEGEoMAAEIQBAAukAgICfwJ+IwBBkAJrIgIkACABQQhqKQMAIQQgASkDACEFIAJBiAFqQQ\
RyIAFB1ABqEG8gAiABKAJQNgKIASACIAJBiAFqQYQBEJcBIQMCQEHYARAJIgINAEHYAUEIQQAoAsyn\
QCIBQQIgARsRBAAACyACIAU3AwAgAiAENwMIIAIgASkDEDcDECACQRhqIAFBGGopAwA3AwAgAkEgai\
ABQSBqKQMANwMAIAJBKGogAUEoaikDADcDACACQTBqIAFBMGopAwA3AwAgAkE4aiABQThqKQMANwMA\
IAJBwABqIAFBwABqKQMANwMAIAJByABqIAFByABqKQMANwMAIAJB0ABqIANBhAEQlwEaIABByJXAAD\
YCBCAAIAI2AgAgA0GQAmokAAukAgICfwJ+IwBBkAJrIgIkACABQQhqKQMAIQQgASkDACEFIAJBiAFq\
QQRyIAFB1ABqEG8gAiABKAJQNgKIASACIAJBiAFqQYQBEJcBIQMCQEHYARAJIgINAEHYAUEIQQAoAs\
ynQCIBQQIgARsRBAAACyACIAU3AwAgAiAENwMIIAIgASkDEDcDECACQRhqIAFBGGopAwA3AwAgAkEg\
aiABQSBqKQMANwMAIAJBKGogAUEoaikDADcDACACQTBqIAFBMGopAwA3AwAgAkE4aiABQThqKQMANw\
MAIAJBwABqIAFBwABqKQMANwMAIAJByABqIAFByABqKQMANwMAIAJB0ABqIANBhAEQlwEaIABB7JXA\
ADYCBCAAIAI2AgAgA0GQAmokAAuDAgEEfyAAIAApAwAgAq1CA4Z8NwMAAkACQAJAAkBBwAAgACgCCC\
IDayIEIAJNDQAgAyACaiIEIANJDQEgBEHBAE8NAiAAQQhqIANqQQRqIAEgAhCXARogACAAKAIIIAJq\
NgIIDwsgAEHMAGohBQJAIANFDQAgA0HBAE8NAyAAQQxqIgYgA2ogASAEEJcBGiAAQQA2AgggBSAGQQ\
EQBCACIARrIQIgASAEaiEBCyAFIAEgAkEGdhAEIABBDGogASACQUBxaiACQT9xIgIQlwEaIAAgAjYC\
CA8LIAMgBEGInMAAEIgBAAsgBEHAAEGInMAAEIUBAAsgA0HAAEGYnMAAEIQBAAuRAgEDfyMAQYABay\
ICJAAgAkEYaiABQdQAEJcBGgJAAkAgAigCGCIDQRBPDQAgAkEYakEEciIEIANqQRAgA2siAyADEJ0B\
GiACQQA2AhggAkEsaiIDIAQQDSACQfAAakEIaiACQeQAaikCADcDACACIAJB3ABqKQIANwNwIAMgAk\
HwAGoQDSACQQhqQQhqIgQgAkE0aikCADcDACACIAIpAiw3AwhBEBAJIgNFDQEgAyACKQMINwAAIANB\
CGogBCkDADcAACABEBAgAEEQNgIEIAAgAzYCACACQYABaiQADwtB9Z7AAEEXIAJB8ABqQfCawABBgJ\
vAABB/AAtBEEEBQQAoAsynQCICQQIgAhsRBAAAC/8BAQR/IAAgACkDACACrXw3AwACQAJAAkACQEHA\
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\
ciABQcwBahBtIAIgASgCyAE2AqACIAJBCGpByAFqIAJBoAJqQcwAEJcBGgJAQZgCEAkiAQ0AQZgCQQ\
hBACgCzKdAIgJBAiACGxEEAAALIAEgAkEIakGYAhCXASEBIABB5JDAADYCBCAAIAE2AgAgAkHwAmok\
AAuaAQEBfyMAQYAEayICJAAgAkEIaiABQcgBEJcBGiACQegCakEEciABQcwBahBuIAIgASgCyAE2Au\
gCIAJBCGpByAFqIAJB6AJqQZQBEJcBGgJAQeACEAkiAQ0AQeACQQhBACgCzKdAIgJBAiACGxEEAAAL\
IAEgAkEIakHgAhCXASEBIABBiJHAADYCBCAAIAE2AgAgAkGABGokAAuaAQEBfyMAQfADayICJAAgAk\
EIaiABQcgBEJcBGiACQeACakEEciABQcwBahBxIAIgASgCyAE2AuACIAJBCGpByAFqIAJB4AJqQYwB\
EJcBGgJAQdgCEAkiAQ0AQdgCQQhBACgCzKdAIgJBAiACGxEEAAALIAEgAkEIakHYAhCXASEBIABBrJ\
HAADYCBCAAIAE2AgAgAkHwA2okAAuaAQEBfyMAQYAEayICJAAgAkEIaiABQcgBEJcBGiACQegCakEE\
ciABQcwBahBuIAIgASgCyAE2AugCIAJBCGpByAFqIAJB6AJqQZQBEJcBGgJAQeACEAkiAQ0AQeACQQ\
hBACgCzKdAIgJBAiACGxEEAAALIAEgAkEIakHgAhCXASEBIABB0JHAADYCBCAAIAE2AgAgAkGABGok\
AAuaAQEBfyMAQbADayICJAAgAkEIaiABQcgBEJcBGiACQcACakEEciABQcwBahBwIAIgASgCyAE2As\
ACIAJBCGpByAFqIAJBwAJqQewAEJcBGgJAQbgCEAkiAQ0AQbgCQQhBACgCzKdAIgJBAiACGxEEAAAL\
IAEgAkEIakG4AhCXASEBIABB9JHAADYCBCAAIAE2AgAgAkGwA2okAAuaAQEBfyMAQfADayICJAAgAk\
EIaiABQcgBEJcBGiACQeACakEEciABQcwBahBxIAIgASgCyAE2AuACIAJBCGpByAFqIAJB4AJqQYwB\
EJcBGgJAQdgCEAkiAQ0AQdgCQQhBACgCzKdAIgJBAiACGxEEAAALIAEgAkEIakHYAhCXASEBIABBmJ\
LAADYCBCAAIAE2AgAgAkHwA2okAAuaAQEBfyMAQfACayICJAAgAkEIaiABQcgBEJcBGiACQaACakEE\
ciABQcwBahBtIAIgASgCyAE2AqACIAJBCGpByAFqIAJBoAJqQcwAEJcBGgJAQZgCEAkiAQ0AQZgCQQ\
hBACgCzKdAIgJBAiACGxEEAAALIAEgAkEIakGYAhCXASEBIABBvJLAADYCBCAAIAE2AgAgAkHwAmok\
AAuaAQEBfyMAQbADayICJAAgAkEIaiABQcgBEJcBGiACQcACakEEciABQcwBahBwIAIgASgCyAE2As\
ACIAJBCGpByAFqIAJBwAJqQewAEJcBGgJAQbgCEAkiAQ0AQbgCQQhBACgCzKdAIgJBAiACGxEEAAAL\
IAEgAkEIakG4AhCXASEBIABB4JLAADYCBCAAIAE2AgAgAkGwA2okAAt/AQF/IwBBwABrIgUkACAFIA\
E2AgwgBSAANgIIIAUgAzYCFCAFIAI2AhAgBUEsakECNgIAIAVBPGpBBDYCACAFQgI3AhwgBUHwj8AA\
NgIYIAVBATYCNCAFIAVBMGo2AiggBSAFQRBqNgI4IAUgBUEIajYCMCAFQRhqIAQQmwEAC34BAn8jAE\
EwayICJAAgAkEUakEBNgIAIAJBhIzAADYCECACQQE2AgwgAkH8i8AANgIIIAFBHGooAgAhAyABKAIY\
IQEgAkEsakECNgIAIAJCAjcCHCACQfCPwAA2AhggAiACQQhqNgIoIAEgAyACQRhqEBwhASACQTBqJA\
AgAQt+AQJ/IwBBMGsiAiQAIAJBFGpBATYCACACQYSMwAA2AhAgAkEBNgIMIAJB/IvAADYCCCABQRxq\
KAIAIQMgASgCGCEBIAJBLGpBAjYCACACQgI3AhwgAkHwj8AANgIYIAIgAkEIajYCKCABIAMgAkEYah\
AcIQEgAkEwaiQAIAELjgEAIABCADcDCCAAQgA3AwAgAEEANgJQIABBACkD2J1ANwMQIABBGGpBACkD\
4J1ANwMAIABBIGpBACkD6J1ANwMAIABBKGpBACkD8J1ANwMAIABBMGpBACkD+J1ANwMAIABBOGpBAC\
kDgJ5ANwMAIABBwABqQQApA4ieQDcDACAAQcgAakEAKQOQnkA3AwALjgEAIABCADcDCCAAQgA3AwAg\
AEEANgJQIABBACkDmJ1ANwMQIABBGGpBACkDoJ1ANwMAIABBIGpBACkDqJ1ANwMAIABBKGpBACkDsJ\
1ANwMAIABBMGpBACkDuJ1ANwMAIABBOGpBACkDwJ1ANwMAIABBwABqQQApA8idQDcDACAAQcgAakEA\
KQPQnUA3AwALbQEBfyMAQTBrIgMkACADIAE2AgQgAyAANgIAIANBHGpBAjYCACADQSxqQQU2AgAgA0\
ICNwIMIANBmI/AADYCCCADQQU2AiQgAyADQSBqNgIYIAMgA0EEajYCKCADIAM2AiAgA0EIaiACEJsB\
AAttAQF/IwBBMGsiAyQAIAMgATYCBCADIAA2AgAgA0EcakECNgIAIANBLGpBBTYCACADQgI3AgwgA0\
HUjsAANgIIIANBBTYCJCADIANBIGo2AhggAyADQQRqNgIoIAMgAzYCICADQQhqIAIQmwEAC20BAX8j\
AEEwayIDJAAgAyABNgIEIAMgADYCACADQRxqQQI2AgAgA0EsakEFNgIAIANCAzcCDCADQYSQwAA2Ag\
ggA0EFNgIkIAMgA0EgajYCGCADIAM2AiggAyADQQRqNgIgIANBCGogAhCbAQALbQEBfyMAQTBrIgMk\
ACADIAE2AgQgAyAANgIAIANBHGpBAjYCACADQSxqQQU2AgAgA0ICNwIMIANBuIzAADYCCCADQQU2Ai\
QgAyADQSBqNgIYIAMgAzYCKCADIANBBGo2AiAgA0EIaiACEJsBAAttAQF/IwBBMGsiAyQAIAMgATYC\
BCADIAA2AgAgA0EcakECNgIAIANBLGpBBTYCACADQgI3AgwgA0G8j8AANgIIIANBBTYCJCADIANBIG\
o2AhggAyADQQRqNgIoIAMgAzYCICADQQhqIAIQmwEAC3ABAX8jAEEwayICJAAgAiABNgIEIAIgADYC\
ACACQRxqQQI2AgAgAkEsakEFNgIAIAJCAjcCDCACQZCWwAA2AgggAkEFNgIkIAIgAkEgajYCGCACIA\
JBBGo2AiggAiACNgIgIAJBCGpBoJbAABCbAQALbAAgAEIANwMAIAAgACkDcDcDCCAAQSBqIABBiAFq\
KQMANwMAIABBGGogAEGAAWopAwA3AwAgAEEQaiAAQfgAaikDADcDACAAQShqQQBBwgAQnQEaAkAgAE\
HwDmoiAC0AAEUNACAAQQA6AAALC2MBAX8jAEEgayICJAAgAiAAKAIANgIEIAJBCGpBEGogAUEQaikC\
ADcDACACQQhqQQhqIAFBCGopAgA3AwAgAiABKQIANwMIIAJBBGpBjIfAACACQQhqEBwhASACQSBqJA\
AgAQt3AQF/QQBBACgC+KNAQQFqNgL4o0ACQAJAAkBBACgCwKdAQQFHDQBBAEEAKALEp0BBAWoiADYC\
xKdAIABBA08NAkEAKALIp0BBf0wNAiAAQQJJDQEMAgtBAEKBgICAEDcDwKdAQQAoAsinQEF/TA0BCx\
DEAQALAAtlAgF/AX4jAEEQayICJAACQAJAIAFFDQAgASgCAA0BIAFBfzYCACACQQhqIAEoAgQgAUEI\
aigCACgCEBEEACACKQMIIQMgAUEANgIAIAAgAzcDACACQRBqJAAPCxCxAQALELIBAAtUAQJ/AkAgAC\
gCACIAQQRqKAIAIABBCGoiAygCACIEayACTw0AIAAgBCACEGwgAygCACEECyAAKAIAIARqIAEgAhCX\
ARogAyADKAIAIAJqNgIAQQALSgEDf0EAIQMCQCACRQ0AAkADQCAALQAAIgQgAS0AACIFRw0BIABBAW\
ohACABQQFqIQEgAkF/aiICRQ0CDAALCyAEIAVrIQMLIAMLUQECfwJAAkAgAEUNACAAKAIADQEgAEEA\
NgIAIAAoAgQhASAAKAIIIQIgABAQIAEgAigCABEBAAJAIAIoAgRFDQAgARAQCw8LELEBAAsQsgEAC0\
4AAkACQCAARQ0AIAAoAgANASAAQX82AgAgACgCBCABIAIgAEEIaigCACgCDBEGAAJAIAJFDQAgARAQ\
CyAAQQA2AgAPCxCxAQALELIBAAtUAQF/AkACQCABQYCAxABGDQBBASEEIAAoAhggASAAQRxqKAIAKA\
IQEQUADQELAkAgAg0AQQAPCyAAKAIYIAIgAyAAQRxqKAIAKAIMEQcAIQQLIAQLWAAgAEIANwMAIABB\
ADYCMCAAQQApA6CbQDcDCCAAQRBqQQApA6ibQDcDACAAQRhqQQApA7CbQDcDACAAQSBqQQApA7ibQD\
cDACAAQShqQQApA8CbQDcDAAtIAQF/IwBBIGsiAyQAIANBFGpBADYCACADQaiiwAA2AhAgA0IBNwIE\
IAMgATYCHCADIAA2AhggAyADQRhqNgIAIAMgAhCbAQALTAAgAEEANgIIIABCADcDACAAQQApAticQD\
cCTCAAQdQAakEAKQLgnEA3AgAgAEHcAGpBACkC6JxANwIAIABB5ABqQQApAvCcQDcCAAtMACAAQQA2\
AgggAEIANwMAIABBACkD+JxANwJMIABB1ABqQQApA4CdQDcCACAAQdwAakEAKQOInUA3AgAgAEHkAG\
pBACkDkJ1ANwIACzYBAX8CQCACRQ0AIAAhAwNAIAMgAS0AADoAACABQQFqIQEgA0EBaiEDIAJBf2oi\
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\
AABrAAAAYSBmb3JtYXR0aW5nIHRyYWl0IGltcGxlbWVudGF0aW9uIHJldHVybmVkIGFuIGVycm9yAA\
YAAAAAAAAAAQAAAGwAAAD4AxAAGAAAAEUCAAAcAAAAbGlicmFyeS9hbGxvYy9zcmMvZm10LnJzIAQQ\
AEkAAABlAQAACQAAAH4vLmNhcmdvL3JlZ2lzdHJ5L3NyYy9naXRodWIuY29tLTFlY2M2Mjk5ZGI5ZW\
M4MjMvYmxha2UzLTAuMy44L3NyYy9saWIucnMAAAAgBBAASQAAAAsCAAAKAAAAIAQQAEkAAAA5AgAA\
CQAAACAEEABJAAAArgIAABkAAAAgBBAASQAAALACAAAJAAAAIAQQAEkAAACwAgAAOAAAAGFzc2VydG\
lvbiBmYWlsZWQ6IG1pZCA8PSBzZWxmLmxlbigpACgPEABNAAAA4wUAAAkAAAAgBBAASQAAAIMCAAAJ\
AAAAIAQQAEkAAACKAgAACgAAACAEEABJAAAAmQMAADMAAAAgBBAASQAAAJoDAAAyAAAAIAQQAEkAAA\
BVBAAAFgAAACAEEABJAAAAZwQAABYAAAAgBBAASQAAAJgEAAASAAAAIAQQAEkAAACiBAAAEgAAAAYA\
AAAEAAAABAAAAG0AAACQBRAASwAAAM0AAAAgAAAAfi8uY2FyZ28vcmVnaXN0cnkvc3JjL2dpdGh1Yi\
5jb20tMWVjYzYyOTlkYjllYzgyMy9hcnJheXZlYy0wLjUuMi9zcmMvbGliLnJzAAYAAAAEAAAABAAA\
AG0AAAAGAAAAIAAAAAEAAABuAAAAIQYQAA0AAAAMBhAAFQAAAGluc3VmZmljaWVudCBjYXBhY2l0eU\
NhcGFjaXR5RXJyb3JQYWRFcnJvcgAAWAYQACAAAAB4BhAAEgAAAAYAAAAAAAAAAQAAAG8AAABpbmRl\
eCBvdXQgb2YgYm91bmRzOiB0aGUgbGVuIGlzICBidXQgdGhlIGluZGV4IGlzIDAwMDEwMjAzMDQwNT\
A2MDcwODA5MTAxMTEyMTMxNDE1MTYxNzE4MTkyMDIxMjIyMzI0MjUyNjI3MjgyOTMwMzEzMjMzMzQz\
NTM2MzczODM5NDA0MTQyNDM0NDQ1NDY0NzQ4NDk1MDUxNTI1MzU0NTU1NjU3NTg1OTYwNjE2MjYzNj\
Q2NTY2Njc2ODY5NzA3MTcyNzM3NDc1NzY3Nzc4Nzk4MDgxODI4Mzg0ODU4Njg3ODg4OTkwOTE5Mjkz\
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\
4FvYngXBXZ27ywfVfDYqKZpiF91wMFoBWZE5WQ732OwvFTELwP9nJjNnERVYaIdKtI6nj/lkDS4M26\
RP+r4dSLVHCMm882fmCWo7p8qEha5nuyv4lP5y82488TYdXzr1T6XRguatf1IOUR9sPiuMaAWba71B\
+6vZgx95IX4TGc3gWygPEABNAAAA6wsAAA0AAAAvcnVzdGMvNTNjYjdiMDliMDBjYmVhODc1NGZmYj\
c4ZTdlM2NiNTIxY2I4YWY0Yi9saWJyYXJ5L2NvcmUvc3JjL3NsaWNlL21vZC5yc3dlIG5ldmVyIHVz\
ZSBpbnB1dF9sYXp5BgAAAAAAAAABAAAAcAAAAKwPEABHAAAAQQAAAAEAAAB+Ly5jYXJnby9yZWdpc3\
RyeS9zcmMvZ2l0aHViLmNvbS0xZWNjNjI5OWRiOWVjODIzL3NoYTMtMC45LjEvc3JjL2xpYi5ycwAU\
EBAATwAAABsAAAANAAAAFBAQAE8AAAAiAAAADQAAAH4vLmNhcmdvL3JlZ2lzdHJ5L3NyYy9naXRodW\
IuY29tLTFlY2M2Mjk5ZGI5ZWM4MjMvYmxvY2stYnVmZmVyLTAuOS4wL3NyYy9saWIucnMArA8QAEcA\
AABIAAAAAQAAAKwPEABHAAAATwAAAAEAAACsDxAARwAAAFYAAAABAAAArA8QAEcAAABmAAAAAQAAAK\
wPEABHAAAAbQAAAAEAAACsDxAARwAAAHQAAAABAAAArA8QAEcAAAB7AAAAAQAAAH4vLmNhcmdvL3Jl\
Z2lzdHJ5L3NyYy9naXRodWIuY29tLTFlY2M2Mjk5ZGI5ZWM4MjMvZ2VuZXJpYy1hcnJheS0wLjE0Lj\
Qvc3JjL2xpYi5ycwAAAGNhbGxlZCBgT3B0aW9uOjp1bndyYXAoKWAgb24gYSBgTm9uZWAgdmFsdWUA\
ZBEQABwAAADsAQAAHgAAAGxpYnJhcnkvc3RkL3NyYy9wYW5pY2tpbmcucnMEAAAAAAAAAG51bGwgcG\
9pbnRlciBwYXNzZWQgdG8gcnVzdHJlY3Vyc2l2ZSB1c2Ugb2YgYW4gb2JqZWN0IGRldGVjdGVkIHdo\
aWNoIHdvdWxkIGxlYWQgdG8gdW5zYWZlIGFsaWFzaW5nIGluIHJ1c3QApeWAgAAEbmFtZQGa5YCAAM\
cBADZ3YXNtX2JpbmRnZW46Ol9fd2JpbmRnZW5fc3RyaW5nX25ldzo6aDg1ZDAzZjY1ODJiZmMxZWQB\
MXdhc21fYmluZGdlbjo6X193YmluZGdlbl90aHJvdzo6aDU2NTkwZWE1ZmNkN2Q0YjMCM3dhc21fYm\
luZGdlbjo6X193YmluZGdlbl9yZXRocm93OjpoN2VmMjVmMjk2ZmZjNzFlMwMvc2hhMjo6c2hhNTEy\
Ojpzb2Z0Ojpjb21wcmVzczo6aGM0M2QxYjA4NzhlYWZiODkEL3NoYTI6OnNoYTI1Njo6c29mdDo6Y2\
9tcHJlc3M6Omg3NDdmNmFkOGQ2ZjNjNDliBQtjcmVhdGVfaGFzaAY2cmlwZW1kMzIwOjpibG9jazo6\
cHJvY2Vzc19tc2dfYmxvY2s6OmgzYjU4YjBkMjc1MDQwZDBkBzZyaXBlbWQxNjA6OmJsb2NrOjpwcm\
9jZXNzX21zZ19ibG9jazo6aGMyYmJkYTk3NDdlMTk1ZGQIK3NoYTE6OmNvbXByZXNzOjpjb21wcmVz\
czo6aGIyNWQwMDU3ZWM2MmM3ZWIJOmRsbWFsbG9jOjpkbG1hbGxvYzo6RGxtYWxsb2M8QT46Om1hbG\
xvYzo6aGRhNDhiMThmMWE5MzBiNzYKNmJsYWtlMzo6cG9ydGFibGU6OmNvbXByZXNzX2luX3BsYWNl\
OjpoNjNlMTI2ZmM5MzZkMzY3MAs/PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Oj\
p1cGRhdGU6Omg2ZGYwNWIxYmEzNDcxOGZiDCdtZDU6OnV0aWxzOjpjb21wcmVzczo6aGM5YTkyZTVh\
ZDhmZjE4YjINL21kMjo6TWQyU3RhdGU6OnByb2Nlc3NfYmxvY2s6Omg1MjgzMmZiYzEyNTFkYmNhDj\
BibGFrZTM6OmNvbXByZXNzX3N1YnRyZWVfd2lkZTo6aDI3ODEyZGE5NzM1OWE4MTAPL21kNDo6TWQ0\
U3RhdGU6OnByb2Nlc3NfYmxvY2s6Omg3NjNlY2ZhN2ZkMmE4MTM4EDhkbG1hbGxvYzo6ZGxtYWxsb2\
M6OkRsbWFsbG9jPEE+OjpmcmVlOjpoMGIzNjc5M2M5NzIxMjMzZhFBZGxtYWxsb2M6OmRsbWFsbG9j\
OjpEbG1hbGxvYzxBPjo6ZGlzcG9zZV9jaHVuazo6aGVjNWMyYWYzZDQyNDY2YmUSK2JsYWtlMzo6SG\
FzaGVyOjpmaW5hbGl6ZTo6aDNmZTdmOTY4MTNmZDFjZDYTIGtlY2Nhazo6ZjE2MDA6OmhiOGVmNmQ1\
M2VhMTEzODVkFCxjb3JlOjpmbXQ6OkZvcm1hdHRlcjo6cGFkOjpoY2M2ZGI3YjU5M2YzYjk2MxUOX1\
9ydXN0X3JlYWxsb2MWYTxzaGEyOjpzaGE1MTI6OlNoYTUxMiBhcyBkaWdlc3Q6OmZpeGVkOjpGaXhl\
ZE91dHB1dERpcnR5Pjo6ZmluYWxpemVfaW50b19kaXJ0eTo6aDFhZTU4YzExODk0ZjYxNTgXMWJsYW\
tlMzo6SGFzaGVyOjptZXJnZV9jdl9zdGFjazo6aDk4OGIxZjlkYWQ2YzIyYTQYRzxEIGFzIGRpZ2Vz\
dDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemVfcmVzZXQ6OmhhNjlmZmJjMjFiODIwZj\
NkGTVjb3JlOjpmbXQ6OkZvcm1hdHRlcjo6cGFkX2ludGVncmFsOjpoOGJkZWJmNmFmZTRjMDFlZBpH\
PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aGUyYT\
IzNjE1OTkxMDI5NGYbRzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxp\
emVfcmVzZXQ6OmgxMWUzMDc2ZWZiZTZlYmM5HCNjb3JlOjpmbXQ6OndyaXRlOjpoZTljNGRjNmIwNT\
gwNDA5NR1hPHNoYTI6OnNoYTUxMjo6U2hhMzg0IGFzIGRpZ2VzdDo6Zml4ZWQ6OkZpeGVkT3V0cHV0\
RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoYTYzMThiYzJjYjRmZjI4Yh5HPEQgYXMgZGlnZX\
N0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aDg5ZTliNTc2M2Q2NDA3\
NDQfQjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25lOjpoMTg4Mz\
c4NTM3ZmE3ODdmNCBXPHNoYTE6OlNoYTEgYXMgZGlnZXN0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0\
eT46OmZpbmFsaXplX2ludG9fZGlydHk6OmgzODg1MjgzMjA5MGFjNGY4IUc8RCBhcyBkaWdlc3Q6Om\
R5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoYzM3ZDYyNWQwN2IzNzhhNSI0\
Ymxha2UzOjpjb21wcmVzc19wYXJlbnRzX3BhcmFsbGVsOjpoMzQ1N2Y2YWI2NWU2NmQxNyNHPEQgYX\
MgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aDRiNWVjM2Mz\
ZWM5YTRhYTUkRzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemVfcm\
VzZXQ6OmhjOGI4MWVjNDM0MjdhMjUyJUE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2Vz\
dD46OmZpbmFsaXplOjpoMmY0OTU5YjM5YzI1YWFiMiZBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0Oj\
pEeW5EaWdlc3Q+OjpmaW5hbGl6ZTo6aDk3MDQ1NWZjZmJlYjZjNzknQTxEIGFzIGRpZ2VzdDo6ZHlu\
X2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemU6OmhiNGY4MTZiNGM2MGVlYmZhKEc8RCBhcyBkaW\
dlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoMTM4OWY4ZmRlZTlk\
OTY4YylHPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldD\
o6aGNkYzQ5ODM2Njg5NWZlMDkqQTxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6\
ZmluYWxpemU6OmhlODUyOTk3YTUxOGRkNWVlK0E8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bk\
RpZ2VzdD46OmZpbmFsaXplOjpoZjI2OGUzMjNjMjA1MGEwMyxBPEQgYXMgZGlnZXN0OjpkeW5fZGln\
ZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZTo6aDg3NzdjMjFmNDhhZWJhZTctRzxEIGFzIGRpZ2VzdD\
o6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemVfcmVzZXQ6OmhjMDk2N2Y0MmU0MTQ2YzY3\
LmE8c2hhMjo6c2hhMjU2OjpTaGEyNTYgYXMgZGlnZXN0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT\
46OmZpbmFsaXplX2ludG9fZGlydHk6OmhhNWZjNDdiZWViZmI4NDQ5L0c8RCBhcyBkaWdlc3Q6OmR5\
bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoMGNlZmEzMzI0ZjQwYTIwMTBBPE\
QgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZTo6aGI2OTRlNTBkYTc0\
ODg0M2MxMnNoYTI6OnNoYTUxMjo6RW5naW5lNTEyOjpmaW5pc2g6Omg0N2M0YWIxNmI1ZWVlYzFlMk\
E8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpoZTJkMWVlMjc1\
OWVhMzE5ZjNHPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZX\
NldDo6aDcxMWU1YTcxOTY1MmI1NWU0RzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0\
Pjo6ZmluYWxpemVfcmVzZXQ6OmhjNTFhMzQwMDY1NzczMDcyNUE8RCBhcyBkaWdlc3Q6OmR5bl9kaW\
dlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpoNWJhOTRjZGY5NzA5NzYwNjZBPEQgYXMgZGlnZXN0\
OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZTo6aGU1ODcwZWM4MGY5YTA5NDA3QTxEIG\
FzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemU6OmhkMmY0OGZkMzU5M2Q4\
ZGIwOEI8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9uZTo6aGVlNT\
RkMGNjMjA5M2IwNGY5RzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxp\
emVfcmVzZXQ6OmgxMzdhYWU1YTc3Nzg0MTI3Okc8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bk\
RpZ2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoMWQzMjllZWMzNTkwNDFmMDs7PCZtdXQgVyBhcyBjb3Jl\
OjpmbXQ6OldyaXRlPjo6d3JpdGVfY2hhcjo6aDczMTIxZmJlMmE5OTBhMmU8LWJsYWtlMzo6Q2h1bm\
tTdGF0ZTo6dXBkYXRlOjpoZDU2Nzk3NzFlMWQxNDNkOT1hPHJpcGVtZDMyMDo6UmlwZW1kMzIwIGFz\
IGRpZ2VzdDo6Zml4ZWQ6OkZpeGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoMj\
k3ZmNmNmI3NjE1MTI2Nj5HPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5h\
bGl6ZV9yZXNldDo6aDE1MjdmNTI1MDgxODUwNTE/RzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RH\
luRGlnZXN0Pjo6ZmluYWxpemVfcmVzZXQ6OmhhMDMwMTYzNjliMjU5MmU3QGE8c2hhMjo6c2hhMjU2\
OjpTaGEyMjQgYXMgZGlnZXN0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG\
9fZGlydHk6Omg5MTY1NTc5OTI1MDg2NTJjQT88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRp\
Z2VzdD46OnVwZGF0ZTo6aDExMWVlOGZhMTY0ZGUwZjhCPzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdD\
o6RHluRGlnZXN0Pjo6dXBkYXRlOjpoMTliYjU5NWFkMTljNGQ5OUM/PEQgYXMgZGlnZXN0OjpkeW5f\
ZGlnZXN0OjpEeW5EaWdlc3Q+Ojp1cGRhdGU6OmgyOGI4ZmZmMGM3M2NmMWQ1RD88RCBhcyBkaWdlc3\
Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aDY4NzI4YWJiZmY4NTE0MDNFQTxEIGFz\
IGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemU6OmhhZmYyZmZjNDFlODFlMm\
NjRkE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpoZmFiNjc3\
Y2M3MTViYWFkZUdBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZT\
o6aDEzNmYwYTExOGMwOWQyZDhIL2NvcmU6OmZtdDo6bnVtOjppbXA6OmZtdF91NjQ6Omg0NDBlYzRi\
N2JmODRmM2UzSTJzaGEyOjpzaGEyNTY6OkVuZ2luZTI1Njo6ZmluaXNoOjpoMDc1ZThjOTBiZDExZm\
VlZkpuZ2VuZXJpY19hcnJheTo6aW1wbHM6OjxpbXBsIGNvcmU6OmNsb25lOjpDbG9uZSBmb3IgZ2Vu\
ZXJpY19hcnJheTo6R2VuZXJpY0FycmF5PFQsTj4+OjpjbG9uZTo6aDljMWI0YzA3NTg1NWU4MmNLWz\
xzaGEzOjpTaGEzXzUxMiBhcyBkaWdlc3Q6OmZpeGVkOjpGaXhlZE91dHB1dERpcnR5Pjo6ZmluYWxp\
emVfaW50b19kaXJ0eTo6aDgwYWI5YTVjZTAxMTYwYjBMXDxzaGEzOjpLZWNjYWs1MTIgYXMgZGlnZX\
N0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG9fZGlydHk6OmhiZjhjMmU3\
N2JiMzRkZjJlTT48RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnJlc2V0OjpoMj\
Q4ZmEzZmU1MGU3NTFlN05hPHJpcGVtZDE2MDo6UmlwZW1kMTYwIGFzIGRpZ2VzdDo6Zml4ZWQ6OkZp\
eGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoYmY1MzJjZWUwOTJiZDMxOU9CPE\
QgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6OmhjZTI3ZDQ2ZDY5\
MmQwYTk3UFU8bWQ1OjpNZDUgYXMgZGlnZXN0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbm\
FsaXplX2ludG9fZGlydHk6OmhmY2NhMTcyNWQ2MGQ0MjYxUVU8bWQ0OjpNZDQgYXMgZGlnZXN0Ojpm\
aXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG9fZGlydHk6OmhhNzNmODUzODY0NT\
FjM2ExUj88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aGExMTU0\
MzY2YWViZWRjNTBTPzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6dXBkYXRlOj\
poYzEyMTE4YWViM2YyY2UzOVQ/PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojp1\
cGRhdGU6Omg4NjcyMTI5MjY2NGVlZTEzVT88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2\
VzdD46OnVwZGF0ZTo6aGY1ZDY2ZjBmOWE5Mjc5MTFWPzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6\
RHluRGlnZXN0Pjo6dXBkYXRlOjpoMzUyMDk2YTNjYmI4Y2Q2MFdHPEQgYXMgZGlnZXN0OjpkeW5fZG\
lnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aDRkNzc4ZmRlMjNkNDQ1YzlYRzxEIGFz\
IGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemVfcmVzZXQ6OmgyYmE3MTQzMT\
BmZGViODQ0WUE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpo\
NTJkMTliZGU5MDViZTc2MlpBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW\
5hbGl6ZTo6aGE5OTI5MjIzZTEwYzZiNzFbXDxzaGEzOjpLZWNjYWszODQgYXMgZGlnZXN0OjpmaXhl\
ZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG9fZGlydHk6OmgxOTA1NGVkN2M3Y2FkNj\
cyXFs8c2hhMzo6U2hhM18zODQgYXMgZGlnZXN0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZp\
bmFsaXplX2ludG9fZGlydHk6OmgwOTQwMmY4MzM2OGQ5NzhkXT88RCBhcyBkaWdlc3Q6OmR5bl9kaW\
dlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aDEzNjE4OGU5OWM5NmIwN2ZeQjxEIGFzIGRpZ2VzdDo6\
ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25lOjpoM2IxYmI0ZDhlMGQ4Mjk4N19CPEQgYX\
MgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6Omg4OWUyZTJhODVjMTYz\
YjFiYD88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aDIwNmUwM2\
UwZmQ0ODVmMTNhQTxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemU6\
OmhlZjY3MzMwYmU1MTNiNWIyYj88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46On\
VwZGF0ZTo6aDJjMGQ1MDI0YjcxNzgzNTZjbmdlbmVyaWNfYXJyYXk6OmltcGxzOjo8aW1wbCBjb3Jl\
OjpjbG9uZTo6Q2xvbmUgZm9yIGdlbmVyaWNfYXJyYXk6OkdlbmVyaWNBcnJheTxULE4+Pjo6Y2xvbm\
U6Omg4MWE5ZTc1YjEyYTAxMjUxZEE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46\
OmZpbmFsaXplOjpoM2IyZDA4MGRlNWVhMTBjNWVBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW\
5EaWdlc3Q+OjpmaW5hbGl6ZTo6aDk5ODE3OGYyZGQwOGUzM2ZmXDxzaGEzOjpLZWNjYWsyMjQgYXMg\
ZGlnZXN0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG9fZGlydHk6Omg5NT\
UyNDlhMmVhYWYzZTdjZ1w8c2hhMzo6S2VjY2FrMjU2IGFzIGRpZ2VzdDo6Zml4ZWQ6OkZpeGVkT3V0\
cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoMzVmNjYwZTNiZjZmZmZlMWhbPHNoYTM6Ol\
NoYTNfMjI0IGFzIGRpZ2VzdDo6Zml4ZWQ6OkZpeGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRv\
X2RpcnR5OjpoNzk5NDFjMDQwNmEzNDI3Y2lbPHNoYTM6OlNoYTNfMjU2IGFzIGRpZ2VzdDo6Zml4ZW\
Q6OkZpeGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoOTk0MDEyZWEyNDJiOTkx\
N2pCPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6OmhhMjVkNj\
AwMWU0MDQ1YTA4a0I8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9u\
ZTo6aGUzNWM1NDcwMDE1YTFiMmNsTmFsbG9jOjpyYXdfdmVjOjpSYXdWZWM8VCxBPjo6cmVzZXJ2ZT\
o6ZG9fcmVzZXJ2ZV9hbmRfaGFuZGxlOjpoODYyNGFiNzE1MTQ5ZWViMm1uZ2VuZXJpY19hcnJheTo6\
aW1wbHM6OjxpbXBsIGNvcmU6OmNsb25lOjpDbG9uZSBmb3IgZ2VuZXJpY19hcnJheTo6R2VuZXJpY0\
FycmF5PFQsTj4+OjpjbG9uZTo6aDAxMTQ3OTBjM2U2ZmNlYjdubmdlbmVyaWNfYXJyYXk6OmltcGxz\
Ojo8aW1wbCBjb3JlOjpjbG9uZTo6Q2xvbmUgZm9yIGdlbmVyaWNfYXJyYXk6OkdlbmVyaWNBcnJheT\
xULE4+Pjo6Y2xvbmU6OmgyNDA0NDY5MTcyMzczOGQ0b25nZW5lcmljX2FycmF5OjppbXBsczo6PGlt\
cGwgY29yZTo6Y2xvbmU6OkNsb25lIGZvciBnZW5lcmljX2FycmF5OjpHZW5lcmljQXJyYXk8VCxOPj\
46OmNsb25lOjpoODdmY2Q0YzQ2N2RjNzc5N3BuZ2VuZXJpY19hcnJheTo6aW1wbHM6OjxpbXBsIGNv\
cmU6OmNsb25lOjpDbG9uZSBmb3IgZ2VuZXJpY19hcnJheTo6R2VuZXJpY0FycmF5PFQsTj4+OjpjbG\
9uZTo6aGE0ODgzZTE4MjY0ZmFiZGFxbmdlbmVyaWNfYXJyYXk6OmltcGxzOjo8aW1wbCBjb3JlOjpj\
bG9uZTo6Q2xvbmUgZm9yIGdlbmVyaWNfYXJyYXk6OkdlbmVyaWNBcnJheTxULE4+Pjo6Y2xvbmU6Om\
hjZGViNzdmN2Y3Yjg2MGI4ckI8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJv\
eF9jbG9uZTo6aDM5MTQxZDI4NzM3YzhiYzFzQjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRG\
lnZXN0Pjo6Ym94X2Nsb25lOjpoOTA4YzM0N2EyNTE3MDU0ZHRCPEQgYXMgZGlnZXN0OjpkeW5fZGln\
ZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6Omg5ZjUyNWI2OTNmOTcyMDVmdUI8RCBhcyBkaWdlc3\
Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9uZTo6aGE2YjY4MWMxZjhjMzVhOTZ2LmFs\
bG9jOjpyYXdfdmVjOjpmaW5pc2hfZ3Jvdzo6aDU1MTQ0YWZiYWZjYTUyMGR3QjxEIGFzIGRpZ2VzdD\
o6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25lOjpoMzlmMWQ5YmU2NDA2MWE0Y3hCPEQg\
YXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6Omg1MTQ1OTQ3MjVkNz\
k2NGRmeUI8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9uZTo6aDU5\
MTg4YmVhMWJlOTQ3Y2N6QjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2\
Nsb25lOjpoNjdkOGJhN2JmY2IyNzc1MntCPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdl\
c3Q+Ojpib3hfY2xvbmU6OmhhYjJlZTQyNjYzMDdlNWZkfEI8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3\
Q6OkR5bkRpZ2VzdD46OmJveF9jbG9uZTo6aGNiMTg0ZmY3YTUwNTY5YTV9QjxEIGFzIGRpZ2VzdDo6\
ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25lOjpoZDQ1ZDA2NzI2MDY5Nzc0YX5CPEQgYX\
MgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6OmhmZjdiN2Y3Y2Y5MmNm\
NTcxfy5jb3JlOjpyZXN1bHQ6OnVud3JhcF9mYWlsZWQ6Omg5YmY5OWJjYTg4YmEwNWRjgAFQPGFycm\
F5dmVjOjplcnJvcnM6OkNhcGFjaXR5RXJyb3I8VD4gYXMgY29yZTo6Zm10OjpEZWJ1Zz46OmZtdDo6\
aDFkNTg1OWMzYTVmMmEzMjSBAVA8YXJyYXl2ZWM6OmVycm9yczo6Q2FwYWNpdHlFcnJvcjxUPiBhcy\
Bjb3JlOjpmbXQ6OkRlYnVnPjo6Zm10OjpoYmYyNTk2ODRjMzZmYzQ0ZoIBPjxEIGFzIGRpZ2VzdDo6\
ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6OmhiMjg3ZDY1ZDg4NzBjNDljgwE+PEQgYXMgZG\
lnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aGI2NmU2Zjg0NzcyN2UyZWOEAUFj\
b3JlOjpzbGljZTo6aW5kZXg6OnNsaWNlX3N0YXJ0X2luZGV4X2xlbl9mYWlsOjpoZjg2NGRiMmY3MG\
NmZTEyZIUBP2NvcmU6OnNsaWNlOjppbmRleDo6c2xpY2VfZW5kX2luZGV4X2xlbl9mYWlsOjpoZDgx\
M2NkY2EwMGVkNTkwZIYBTmNvcmU6OnNsaWNlOjo8aW1wbCBbVF0+Ojpjb3B5X2Zyb21fc2xpY2U6Om\
xlbl9taXNtYXRjaF9mYWlsOjpoODU3Mjc3ZGYwMzg3N2ZmOIcBNmNvcmU6OnBhbmlja2luZzo6cGFu\
aWNfYm91bmRzX2NoZWNrOjpoYjE1MTc3ZTA2NzkyMzIxNYgBPWNvcmU6OnNsaWNlOjppbmRleDo6c2\
xpY2VfaW5kZXhfb3JkZXJfZmFpbDo6aGU1M2ZmMzYxNjAwYzhiZTGJATdnZW5lcmljX2FycmF5Ojpm\
cm9tX2l0ZXJfbGVuZ3RoX2ZhaWw6OmhjZTQ1MWY0ZTFiMTBiMzk2igE+PEQgYXMgZGlnZXN0OjpkeW\
5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aDMyYmE3ZWY0NjIzNjZlNDiLATo8Jm11dCBXIGFz\
IGNvcmU6OmZtdDo6V3JpdGU+Ojp3cml0ZV9mbXQ6OmgzMGY1MjA1YjU0YjE4OGE4jAE3c3RkOjpwYW\
5pY2tpbmc6OnJ1c3RfcGFuaWNfd2l0aF9ob29rOjpoYmRiY2ViNWNkMTU4YmYxOY0BC2RpZ2VzdF9o\
YXNojgE6PCZtdXQgVyBhcyBjb3JlOjpmbXQ6OldyaXRlPjo6d3JpdGVfc3RyOjpoYmI3NTg3MzRkNW\
I0MTlkYY8BBGJjbXCQARNfX3diZ19kZW5vaGFzaF9mcmVlkQELdXBkYXRlX2hhc2iSAUNjb3JlOjpm\
bXQ6OkZvcm1hdHRlcjo6cGFkX2ludGVncmFsOjp3cml0ZV9wcmVmaXg6OmhiZjQ2MzQ3Y2VjY2NmNT\
NlkwE+PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aDlmNTBkZDky\
NWNjYTRiZGOUASljb3JlOjpwYW5pY2tpbmc6OnBhbmljOjpoNWJmZGZhYTNkYjlhNGI0YZUBPjxEIG\
FzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6Omg0OTNjMzNjNzZlZjVkOGFk\
lgE+PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aGI4MWZlMmRmYz\
E4ZjA1OGSXAQZtZW1jcHmYARFydXN0X2JlZ2luX3Vud2luZJkBPjxEIGFzIGRpZ2VzdDo6ZHluX2Rp\
Z2VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6OmhjNWFlZDI0ZTg3ZjAwMjM5mgE+PEQgYXMgZGlnZXN0Oj\
pkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aDI4NDQzNTUxMTE5Mzk2YjKbAS1jb3JlOjpw\
YW5pY2tpbmc6OnBhbmljX2ZtdDo6aDNhYjU0MTcxNTViN2JhM2KcAUlzdGQ6OnN5c19jb21tb246Om\
JhY2t0cmFjZTo6X19ydXN0X2VuZF9zaG9ydF9iYWNrdHJhY2U6OmhjNzYwODE2MWE0NjdjMDAynQEG\
bWVtc2V0ngERX193YmluZGdlbl9tYWxsb2OfAT48RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bk\
RpZ2VzdD46OnJlc2V0OjpoM2Q5MTYwNDRiMzhlOTAzOaABEl9fd2JpbmRnZW5fcmVhbGxvY6EBQ3N0\
ZDo6cGFuaWNraW5nOjpiZWdpbl9wYW5pY19oYW5kbGVyOjp7e2Nsb3N1cmV9fTo6aDk5OTViYjJmMG\
RlNGJiMziiATtjb3JlOjpwdHI6OmRyb3BfaW5fcGxhY2U8Ymxha2UzOjpIYXNoZXI+OjpoYmM0Yjkz\
YTU0Y2FjYzM1Y6MBRTxibG9ja19wYWRkaW5nOjpQYWRFcnJvciBhcyBjb3JlOjpmbXQ6OkRlYnVnPj\
o6Zm10OjpoODJjY2Y1Y2Q1ZWYxMjM2MaQBPjxjb3JlOjpmbXQ6OkVycm9yIGFzIGNvcmU6OmZtdDo6\
RGVidWc+OjpmbXQ6Omg5MmFkODFmMzJjNDQzNGQwpQEyY29yZTo6b3B0aW9uOjpPcHRpb248VD46On\
Vud3JhcDo6aDdiNTUxODMzMjE2Yzg4NjamATA8JlQgYXMgY29yZTo6Zm10OjpEZWJ1Zz46OmZtdDo6\
aDdiNDBkZDdlMTg5NjNhMjmnATI8JlQgYXMgY29yZTo6Zm10OjpEaXNwbGF5Pjo6Zm10OjpoOGE0Yj\
c0NGUwNDJjYWRlNagBTjxJIGFzIGNvcmU6Oml0ZXI6OnRyYWl0czo6Y29sbGVjdDo6SW50b0l0ZXJh\
dG9yPjo6aW50b19pdGVyOjpoOTdhMDEzZjljYmEyYjljYakBPjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2\
VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6OmgyNjJmNjgzZjNiYTNjMWQxqgE+PEQgYXMgZGlnZXN0Ojpk\
eW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aDI4NTc5ZDI0NDE5MDY2ZTOrAT48RCBhcyBkaW\
dlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnJlc2V0OjpoOGI0NWYwY2U5OGZlZmIzYawBPjxE\
IGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6OmhhOWY4YzhiMDU3MTUyNm\
U3rQEPX193YmluZGdlbl9mcmVlrgE0YWxsb2M6OnJhd192ZWM6OmNhcGFjaXR5X292ZXJmbG93Ojpo\
NDA3ZTZjZDE3ZTJkYTViNa8BOWNvcmU6Om9wczo6ZnVuY3Rpb246OkZuT25jZTo6Y2FsbF9vbmNlOj\
poYjVlN2Y4Y2Y1Nzk5OWFkN7ABH19fd2JpbmRnZW5fYWRkX3RvX3N0YWNrX3BvaW50ZXKxATF3YXNt\
X2JpbmRnZW46Ol9fcnQ6OnRocm93X251bGw6OmhjOTdlYTYyNDJlZjE5ODc2sgEyd2FzbV9iaW5kZ2\
VuOjpfX3J0Ojpib3Jyb3dfZmFpbDo6aGVjMjk4OTI4NWFjZTYyY2SzAU5jb3JlOjpmbXQ6Om51bTo6\
aW1wOjo8aW1wbCBjb3JlOjpmbXQ6OkRpc3BsYXkgZm9yIHUzMj46OmZtdDo6aDY0NWY0NWE5MWU3MT\
VjODW0ASp3YXNtX2JpbmRnZW46OnRocm93X3N0cjo6aGZiZDk3MTE3NjVlZTdkMWS1ASp3YXNtX2Jp\
bmRnZW46OnRocm93X3ZhbDo6aGY5ZDMxMzhhYjBiYzAxMDe2ATE8VCBhcyBjb3JlOjphbnk6OkFueT\
46OnR5cGVfaWQ6OmgyOWRlYzgxMzgyZDNkNmE0twFEPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpE\
eW5EaWdlc3Q+OjpvdXRwdXRfc2l6ZTo6aDE4NWZiM2MzZDI5YWZhNGW4AUQ8RCBhcyBkaWdlc3Q6Om\
R5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46Om91dHB1dF9zaXplOjpoMTlkNTc3YjNmNzkwZTY5NLkBRDxE\
IGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6b3V0cHV0X3NpemU6Omg3MDZlZTQzNW\
Q0MWJjNjViugFEPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpvdXRwdXRfc2l6\
ZTo6aDcxZTY2Nzc2NWRiNWVkY2O7AUQ8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD\
46Om91dHB1dF9zaXplOjpoMzQzMWViNGQ5OWU3MTNmY7wBRDxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2Vz\
dDo6RHluRGlnZXN0Pjo6b3V0cHV0X3NpemU6Omg3OGFjNGIxODczNTZhNmI2vQFEPEQgYXMgZGlnZX\
N0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpvdXRwdXRfc2l6ZTo6aDViZThjNjllMDU5ODM5Zje+\
AUQ8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46Om91dHB1dF9zaXplOjpoNmNiNT\
RmMmI0NWE2OGQ2Nr8BRDxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6b3V0cHV0\
X3NpemU6OmhhNDAyMjZlNmY4MzU1ZjI3wAFEPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaW\
dlc3Q+OjpvdXRwdXRfc2l6ZTo6aDJkOTEzYjllOWYzNThhYmPBAUQ8RCBhcyBkaWdlc3Q6OmR5bl9k\
aWdlc3Q6OkR5bkRpZ2VzdD46Om91dHB1dF9zaXplOjpoZDg0NzI3NGM0MDY3OTRkMcIBRDxEIGFzIG\
RpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6b3V0cHV0X3NpemU6Omg4MjUzN2Y2ZTdkNWJk\
ZmNhwwFEPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpvdXRwdXRfc2l6ZTo6aG\
IwZWM2MGQ5YmI4YjE4NDTEAQpydXN0X3BhbmljxQE3c3RkOjphbGxvYzo6ZGVmYXVsdF9hbGxvY19l\
cnJvcl9ob29rOjpoMDZmYjkxMTY3MjYwOWRkN8YBb2NvcmU6OnB0cjo6ZHJvcF9pbl9wbGFjZTwmY2\
9yZTo6aXRlcjo6YWRhcHRlcnM6OmNvcGllZDo6Q29waWVkPGNvcmU6OnNsaWNlOjppdGVyOjpJdGVy\
PHU4Pj4+OjpoNTRmNjAzZDg5NDA0ZWEyMgDvgICAAAlwcm9kdWNlcnMCCGxhbmd1YWdlAQRSdXN0AA\
xwcm9jZXNzZWQtYnkDBXJ1c3RjHTEuNTMuMCAoNTNjYjdiMDliIDIwMjEtMDYtMTcpBndhbHJ1cwYw\
LjE5LjAMd2FzbS1iaW5kZ2VuBjAuMi43NA=="));
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const wasm = wasmInstance.exports;
const hexTable = new TextEncoder().encode("0123456789abcdef");
function encode1(src) {
    const dst = new Uint8Array(src.length * 2);
    for(let i = 0; i < dst.length; i++){
        const v = src[i];
        dst[i * 2] = hexTable[v >> 4];
        dst[i * 2 + 1] = hexTable[v & 15];
    }
    return dst;
}
class Hash {
    #hash;
    #digested;
    constructor(algorithm){
        this.#hash = create_hash(algorithm);
        this.#digested = false;
    }
    update(message) {
        let view;
        if (message instanceof Uint8Array) {
            view = message;
        } else if (typeof message === "string") {
            view = new TextEncoder().encode(message);
        } else if (ArrayBuffer.isView(message)) {
            view = new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
        } else if (message instanceof ArrayBuffer) {
            view = new Uint8Array(message);
        } else {
            throw new Error("hash: `data` is invalid type");
        }
        const chunkSize = 65536;
        for(let offset = 0; offset < view.byteLength; offset += chunkSize){
            update_hash(this.#hash, new Uint8Array(view.buffer, view.byteOffset + offset, Math.min(65536, view.byteLength - offset)));
        }
        return this;
    }
    digest() {
        if (this.#digested) throw new Error("hash: already digested");
        this.#digested = true;
        return digest_hash(this.#hash);
    }
    toString(format = "hex") {
        const finalized = new Uint8Array(this.digest());
        switch(format){
            case "hex":
                return new TextDecoder().decode(encode1(finalized));
            case "base64":
                return encode(finalized);
            default:
                throw new Error("hash: invalid format");
        }
    }
}
function createHash(algorithm1) {
    return new Hash(algorithm1);
}
const HEX_CHARS = "0123456789abcdef".split("");
const EXTRA = [
    -2147483648,
    8388608,
    32768,
    128
];
const SHIFT = [
    24,
    16,
    8,
    0
];
const K = [
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298, 
];
const blocks = [];
class Sha256 {
    #block;
    #blocks;
    #bytes;
    #finalized;
    #first;
    #h0;
    #h1;
    #h2;
    #h3;
    #h4;
    #h5;
    #h6;
    #h7;
    #hashed;
    #hBytes;
    #is224;
    #lastByteIndex = 0;
    #start;
    constructor(is2241 = false, sharedMemory1 = false){
        this.init(is2241, sharedMemory1);
    }
    init(is224, sharedMemory) {
        if (sharedMemory) {
            blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            this.#blocks = blocks;
        } else {
            this.#blocks = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ];
        }
        if (is224) {
            this.#h0 = 3238371032;
            this.#h1 = 914150663;
            this.#h2 = 812702999;
            this.#h3 = 4144912697;
            this.#h4 = 4290775857;
            this.#h5 = 1750603025;
            this.#h6 = 1694076839;
            this.#h7 = 3204075428;
        } else {
            this.#h0 = 1779033703;
            this.#h1 = 3144134277;
            this.#h2 = 1013904242;
            this.#h3 = 2773480762;
            this.#h4 = 1359893119;
            this.#h5 = 2600822924;
            this.#h6 = 528734635;
            this.#h7 = 1541459225;
        }
        this.#block = this.#start = this.#bytes = this.#hBytes = 0;
        this.#finalized = this.#hashed = false;
        this.#first = true;
        this.#is224 = is224;
    }
    update(message) {
        if (this.#finalized) {
            return this;
        }
        let msg;
        if (message instanceof ArrayBuffer) {
            msg = new Uint8Array(message);
        } else {
            msg = message;
        }
        let index = 0;
        const length = msg.length;
        const blocks1 = this.#blocks;
        while(index < length){
            let i;
            if (this.#hashed) {
                this.#hashed = false;
                blocks1[0] = this.#block;
                blocks1[16] = blocks1[1] = blocks1[2] = blocks1[3] = blocks1[4] = blocks1[5] = blocks1[6] = blocks1[7] = blocks1[8] = blocks1[9] = blocks1[10] = blocks1[11] = blocks1[12] = blocks1[13] = blocks1[14] = blocks1[15] = 0;
            }
            if (typeof msg !== "string") {
                for(i = this.#start; index < length && i < 64; ++index){
                    blocks1[i >> 2] |= msg[index] << SHIFT[(i++) & 3];
                }
            } else {
                for(i = this.#start; index < length && i < 64; ++index){
                    let code = msg.charCodeAt(index);
                    if (code < 128) {
                        blocks1[i >> 2] |= code << SHIFT[(i++) & 3];
                    } else if (code < 2048) {
                        blocks1[i >> 2] |= (192 | code >> 6) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code & 63) << SHIFT[(i++) & 3];
                    } else if (code < 55296 || code >= 57344) {
                        blocks1[i >> 2] |= (224 | code >> 12) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code & 63) << SHIFT[(i++) & 3];
                    } else {
                        code = 65536 + ((code & 1023) << 10 | msg.charCodeAt(++index) & 1023);
                        blocks1[i >> 2] |= (240 | code >> 18) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code >> 12 & 63) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code & 63) << SHIFT[(i++) & 3];
                    }
                }
            }
            this.#lastByteIndex = i;
            this.#bytes += i - this.#start;
            if (i >= 64) {
                this.#block = blocks1[16];
                this.#start = i - 64;
                this.hash();
                this.#hashed = true;
            } else {
                this.#start = i;
            }
        }
        if (this.#bytes > 4294967295) {
            this.#hBytes += this.#bytes / 4294967296 << 0;
            this.#bytes = this.#bytes % 4294967296;
        }
        return this;
    }
    finalize() {
        if (this.#finalized) {
            return;
        }
        this.#finalized = true;
        const blocks1 = this.#blocks;
        const i = this.#lastByteIndex;
        blocks1[16] = this.#block;
        blocks1[i >> 2] |= EXTRA[i & 3];
        this.#block = blocks1[16];
        if (i >= 56) {
            if (!this.#hashed) {
                this.hash();
            }
            blocks1[0] = this.#block;
            blocks1[16] = blocks1[1] = blocks1[2] = blocks1[3] = blocks1[4] = blocks1[5] = blocks1[6] = blocks1[7] = blocks1[8] = blocks1[9] = blocks1[10] = blocks1[11] = blocks1[12] = blocks1[13] = blocks1[14] = blocks1[15] = 0;
        }
        blocks1[14] = this.#hBytes << 3 | this.#bytes >>> 29;
        blocks1[15] = this.#bytes << 3;
        this.hash();
    }
    hash() {
        let a = this.#h0;
        let b = this.#h1;
        let c = this.#h2;
        let d = this.#h3;
        let e = this.#h4;
        let f = this.#h5;
        let g = this.#h6;
        let h = this.#h7;
        const blocks1 = this.#blocks;
        let s0;
        let s1;
        let maj;
        let t1;
        let t2;
        let ch;
        let ab;
        let da;
        let cd;
        let bc;
        for(let j = 16; j < 64; ++j){
            t1 = blocks1[j - 15];
            s0 = (t1 >>> 7 | t1 << 25) ^ (t1 >>> 18 | t1 << 14) ^ t1 >>> 3;
            t1 = blocks1[j - 2];
            s1 = (t1 >>> 17 | t1 << 15) ^ (t1 >>> 19 | t1 << 13) ^ t1 >>> 10;
            blocks1[j] = blocks1[j - 16] + s0 + blocks1[j - 7] + s1 << 0;
        }
        bc = b & c;
        for(let j1 = 0; j1 < 64; j1 += 4){
            if (this.#first) {
                if (this.#is224) {
                    ab = 300032;
                    t1 = blocks1[0] - 1413257819;
                    h = t1 - 150054599 << 0;
                    d = t1 + 24177077 << 0;
                } else {
                    ab = 704751109;
                    t1 = blocks1[0] - 210244248;
                    h = t1 - 1521486534 << 0;
                    d = t1 + 143694565 << 0;
                }
                this.#first = false;
            } else {
                s0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
                s1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
                ab = a & b;
                maj = ab ^ a & c ^ bc;
                ch = e & f ^ ~e & g;
                t1 = h + s1 + ch + K[j1] + blocks1[j1];
                t2 = s0 + maj;
                h = d + t1 << 0;
                d = t1 + t2 << 0;
            }
            s0 = (d >>> 2 | d << 30) ^ (d >>> 13 | d << 19) ^ (d >>> 22 | d << 10);
            s1 = (h >>> 6 | h << 26) ^ (h >>> 11 | h << 21) ^ (h >>> 25 | h << 7);
            da = d & a;
            maj = da ^ d & b ^ ab;
            ch = h & e ^ ~h & f;
            t1 = g + s1 + ch + K[j1 + 1] + blocks1[j1 + 1];
            t2 = s0 + maj;
            g = c + t1 << 0;
            c = t1 + t2 << 0;
            s0 = (c >>> 2 | c << 30) ^ (c >>> 13 | c << 19) ^ (c >>> 22 | c << 10);
            s1 = (g >>> 6 | g << 26) ^ (g >>> 11 | g << 21) ^ (g >>> 25 | g << 7);
            cd = c & d;
            maj = cd ^ c & a ^ da;
            ch = g & h ^ ~g & e;
            t1 = f + s1 + ch + K[j1 + 2] + blocks1[j1 + 2];
            t2 = s0 + maj;
            f = b + t1 << 0;
            b = t1 + t2 << 0;
            s0 = (b >>> 2 | b << 30) ^ (b >>> 13 | b << 19) ^ (b >>> 22 | b << 10);
            s1 = (f >>> 6 | f << 26) ^ (f >>> 11 | f << 21) ^ (f >>> 25 | f << 7);
            bc = b & c;
            maj = bc ^ b & d ^ cd;
            ch = f & g ^ ~f & h;
            t1 = e + s1 + ch + K[j1 + 3] + blocks1[j1 + 3];
            t2 = s0 + maj;
            e = a + t1 << 0;
            a = t1 + t2 << 0;
        }
        this.#h0 = this.#h0 + a << 0;
        this.#h1 = this.#h1 + b << 0;
        this.#h2 = this.#h2 + c << 0;
        this.#h3 = this.#h3 + d << 0;
        this.#h4 = this.#h4 + e << 0;
        this.#h5 = this.#h5 + f << 0;
        this.#h6 = this.#h6 + g << 0;
        this.#h7 = this.#h7 + h << 0;
    }
    hex() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        const h5 = this.#h5;
        const h6 = this.#h6;
        const h7 = this.#h7;
        let hex = HEX_CHARS[h0 >> 28 & 15] + HEX_CHARS[h0 >> 24 & 15] + HEX_CHARS[h0 >> 20 & 15] + HEX_CHARS[h0 >> 16 & 15] + HEX_CHARS[h0 >> 12 & 15] + HEX_CHARS[h0 >> 8 & 15] + HEX_CHARS[h0 >> 4 & 15] + HEX_CHARS[h0 & 15] + HEX_CHARS[h1 >> 28 & 15] + HEX_CHARS[h1 >> 24 & 15] + HEX_CHARS[h1 >> 20 & 15] + HEX_CHARS[h1 >> 16 & 15] + HEX_CHARS[h1 >> 12 & 15] + HEX_CHARS[h1 >> 8 & 15] + HEX_CHARS[h1 >> 4 & 15] + HEX_CHARS[h1 & 15] + HEX_CHARS[h2 >> 28 & 15] + HEX_CHARS[h2 >> 24 & 15] + HEX_CHARS[h2 >> 20 & 15] + HEX_CHARS[h2 >> 16 & 15] + HEX_CHARS[h2 >> 12 & 15] + HEX_CHARS[h2 >> 8 & 15] + HEX_CHARS[h2 >> 4 & 15] + HEX_CHARS[h2 & 15] + HEX_CHARS[h3 >> 28 & 15] + HEX_CHARS[h3 >> 24 & 15] + HEX_CHARS[h3 >> 20 & 15] + HEX_CHARS[h3 >> 16 & 15] + HEX_CHARS[h3 >> 12 & 15] + HEX_CHARS[h3 >> 8 & 15] + HEX_CHARS[h3 >> 4 & 15] + HEX_CHARS[h3 & 15] + HEX_CHARS[h4 >> 28 & 15] + HEX_CHARS[h4 >> 24 & 15] + HEX_CHARS[h4 >> 20 & 15] + HEX_CHARS[h4 >> 16 & 15] + HEX_CHARS[h4 >> 12 & 15] + HEX_CHARS[h4 >> 8 & 15] + HEX_CHARS[h4 >> 4 & 15] + HEX_CHARS[h4 & 15] + HEX_CHARS[h5 >> 28 & 15] + HEX_CHARS[h5 >> 24 & 15] + HEX_CHARS[h5 >> 20 & 15] + HEX_CHARS[h5 >> 16 & 15] + HEX_CHARS[h5 >> 12 & 15] + HEX_CHARS[h5 >> 8 & 15] + HEX_CHARS[h5 >> 4 & 15] + HEX_CHARS[h5 & 15] + HEX_CHARS[h6 >> 28 & 15] + HEX_CHARS[h6 >> 24 & 15] + HEX_CHARS[h6 >> 20 & 15] + HEX_CHARS[h6 >> 16 & 15] + HEX_CHARS[h6 >> 12 & 15] + HEX_CHARS[h6 >> 8 & 15] + HEX_CHARS[h6 >> 4 & 15] + HEX_CHARS[h6 & 15];
        if (!this.#is224) {
            hex += HEX_CHARS[h7 >> 28 & 15] + HEX_CHARS[h7 >> 24 & 15] + HEX_CHARS[h7 >> 20 & 15] + HEX_CHARS[h7 >> 16 & 15] + HEX_CHARS[h7 >> 12 & 15] + HEX_CHARS[h7 >> 8 & 15] + HEX_CHARS[h7 >> 4 & 15] + HEX_CHARS[h7 & 15];
        }
        return hex;
    }
    toString() {
        return this.hex();
    }
    digest() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        const h5 = this.#h5;
        const h6 = this.#h6;
        const h7 = this.#h7;
        const arr = [
            h0 >> 24 & 255,
            h0 >> 16 & 255,
            h0 >> 8 & 255,
            h0 & 255,
            h1 >> 24 & 255,
            h1 >> 16 & 255,
            h1 >> 8 & 255,
            h1 & 255,
            h2 >> 24 & 255,
            h2 >> 16 & 255,
            h2 >> 8 & 255,
            h2 & 255,
            h3 >> 24 & 255,
            h3 >> 16 & 255,
            h3 >> 8 & 255,
            h3 & 255,
            h4 >> 24 & 255,
            h4 >> 16 & 255,
            h4 >> 8 & 255,
            h4 & 255,
            h5 >> 24 & 255,
            h5 >> 16 & 255,
            h5 >> 8 & 255,
            h5 & 255,
            h6 >> 24 & 255,
            h6 >> 16 & 255,
            h6 >> 8 & 255,
            h6 & 255, 
        ];
        if (!this.#is224) {
            arr.push(h7 >> 24 & 255, h7 >> 16 & 255, h7 >> 8 & 255, h7 & 255);
        }
        return arr;
    }
    array() {
        return this.digest();
    }
    arrayBuffer() {
        this.finalize();
        const buffer = new ArrayBuffer(this.#is224 ? 28 : 32);
        const dataView = new DataView(buffer);
        dataView.setUint32(0, this.#h0);
        dataView.setUint32(4, this.#h1);
        dataView.setUint32(8, this.#h2);
        dataView.setUint32(12, this.#h3);
        dataView.setUint32(16, this.#h4);
        dataView.setUint32(20, this.#h5);
        dataView.setUint32(24, this.#h6);
        if (!this.#is224) {
            dataView.setUint32(28, this.#h7);
        }
        return buffer;
    }
}
class HmacSha256 extends Sha256 {
    #inner;
    #is224;
    #oKeyPad;
    #sharedMemory;
    constructor(secretKey, is2242 = false, sharedMemory2 = false){
        super(is2242, sharedMemory2);
        let key4;
        if (typeof secretKey === "string") {
            const bytes = [];
            const length = secretKey.length;
            let index = 0;
            for(let i = 0; i < length; ++i){
                let code = secretKey.charCodeAt(i);
                if (code < 128) {
                    bytes[index++] = code;
                } else if (code < 2048) {
                    bytes[index++] = 192 | code >> 6;
                    bytes[index++] = 128 | code & 63;
                } else if (code < 55296 || code >= 57344) {
                    bytes[index++] = 224 | code >> 12;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                } else {
                    code = 65536 + ((code & 1023) << 10 | secretKey.charCodeAt(++i) & 1023);
                    bytes[index++] = 240 | code >> 18;
                    bytes[index++] = 128 | code >> 12 & 63;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                }
            }
            key4 = bytes;
        } else {
            if (secretKey instanceof ArrayBuffer) {
                key4 = new Uint8Array(secretKey);
            } else {
                key4 = secretKey;
            }
        }
        if (key4.length > 64) {
            key4 = new Sha256(is2242, true).update(key4).array();
        }
        const oKeyPad = [];
        const iKeyPad = [];
        for(let i = 0; i < 64; ++i){
            const b = key4[i] || 0;
            oKeyPad[i] = 92 ^ b;
            iKeyPad[i] = 54 ^ b;
        }
        this.update(iKeyPad);
        this.#oKeyPad = oKeyPad;
        this.#inner = true;
        this.#is224 = is2242;
        this.#sharedMemory = sharedMemory2;
    }
    finalize() {
        super.finalize();
        if (this.#inner) {
            this.#inner = false;
            const innerHash = this.array();
            super.init(this.#is224, this.#sharedMemory);
            this.update(this.#oKeyPad);
            this.update(innerHash);
            super.finalize();
        }
    }
}
class DenoStdInternalError extends Error {
    constructor(message2){
        super(message2);
        this.name = "DenoStdInternalError";
    }
}
function assert(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError(msg);
    }
}
const MIN_READ = 32 * 1024;
const MAX_SIZE = 2 ** 32 - 2;
class Buffer {
    #buf;
    #off = 0;
    constructor(ab){
        this.#buf = ab === undefined ? new Uint8Array(0) : new Uint8Array(ab);
    }
    bytes(options = {
        copy: true
    }) {
        if (options.copy === false) return this.#buf.subarray(this.#off);
        return this.#buf.slice(this.#off);
    }
    empty() {
        return this.#buf.byteLength <= this.#off;
    }
    get length() {
        return this.#buf.byteLength - this.#off;
    }
    get capacity() {
        return this.#buf.buffer.byteLength;
    }
    truncate(n) {
        if (n === 0) {
            this.reset();
            return;
        }
        if (n < 0 || n > this.length) {
            throw Error("bytes.Buffer: truncation out of range");
        }
        this.#reslice(this.#off + n);
    }
    reset() {
        this.#reslice(0);
        this.#off = 0;
    }
     #tryGrowByReslice(n) {
        const l = this.#buf.byteLength;
        if (n <= this.capacity - l) {
            this.#reslice(l + n);
            return l;
        }
        return -1;
    }
     #reslice(len) {
        assert(len <= this.#buf.buffer.byteLength);
        this.#buf = new Uint8Array(this.#buf.buffer, 0, len);
    }
    readSync(p) {
        if (this.empty()) {
            this.reset();
            if (p.byteLength === 0) {
                return 0;
            }
            return null;
        }
        const nread = copy(this.#buf.subarray(this.#off), p);
        this.#off += nread;
        return nread;
    }
    read(p) {
        const rr = this.readSync(p);
        return Promise.resolve(rr);
    }
    writeSync(p) {
        const m = this.#grow(p.byteLength);
        return copy(p, this.#buf, m);
    }
    write(p) {
        const n = this.writeSync(p);
        return Promise.resolve(n);
    }
     #grow(n) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i1 = this.#tryGrowByReslice(n);
        if (i1 >= 0) {
            return i1;
        }
        const c = this.capacity;
        if (n <= Math.floor(c / 2) - m) {
            copy(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n > MAX_SIZE) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE));
            copy(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n, MAX_SIZE));
        return m;
    }
    grow(n) {
        if (n < 0) {
            throw Error("Buffer.grow: negative count");
        }
        const m = this.#grow(n);
        this.#reslice(m);
    }
    async readFrom(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = await r.read(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
    readFromSync(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = r.readSync(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
}
const ANSI_PATTERN = new RegExp([
    "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
    "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))", 
].join("|"), "g");
var DiffType;
(function(DiffType1) {
    DiffType1["removed"] = "removed";
    DiffType1["common"] = "common";
    DiffType1["added"] = "added";
})(DiffType || (DiffType = {
}));
class AssertionError extends Error {
    constructor(message1){
        super(message1);
        this.name = "AssertionError";
    }
}
function assert1(expr, msg = "") {
    if (!expr) {
        throw new AssertionError(msg);
    }
}
const DEFAULT_BUFFER_SIZE = 32 * 1024;
async function readAll(r) {
    const buf = new Buffer();
    await buf.readFrom(r);
    return buf.bytes();
}
async function writeAll(w, arr) {
    let nwritten = 0;
    while(nwritten < arr.length){
        nwritten += await w.write(arr.subarray(nwritten));
    }
}
function writeAllSync(w, arr) {
    let nwritten = 0;
    while(nwritten < arr.length){
        nwritten += w.writeSync(arr.subarray(nwritten));
    }
}
async function* iter(r, options2) {
    const bufSize = options2?.bufSize ?? DEFAULT_BUFFER_SIZE;
    const b = new Uint8Array(bufSize);
    while(true){
        const result = await r.read(b);
        if (result === null) {
            break;
        }
        yield b.subarray(0, result);
    }
}
async function copy1(src, dst, options2) {
    let n = 0;
    const bufSize = options2?.bufSize ?? DEFAULT_BUFFER_SIZE;
    const b = new Uint8Array(bufSize);
    let gotEOF = false;
    while(gotEOF === false){
        const result = await src.read(b);
        if (result === null) {
            gotEOF = true;
        } else {
            let nwritten = 0;
            while(nwritten < result){
                nwritten += await dst.write(b.subarray(nwritten, result));
            }
            n += nwritten;
        }
    }
    return n;
}
const DEFAULT_BUF_SIZE = 4096;
const MIN_BUF_SIZE = 16;
const CR = "\r".charCodeAt(0);
const LF = "\n".charCodeAt(0);
class BufferFullError extends Error {
    partial;
    name = "BufferFullError";
    constructor(partial1){
        super("Buffer full");
        this.partial = partial1;
    }
}
class PartialReadError extends Error {
    name = "PartialReadError";
    partial;
    constructor(){
        super("Encountered UnexpectedEof, data only partially read");
    }
}
class BufReader {
    buf;
    rd;
    r = 0;
    w = 0;
    eof = false;
    static create(r, size = 4096) {
        return r instanceof BufReader ? r : new BufReader(r, size);
    }
    constructor(rd1, size1 = 4096){
        if (size1 < 16) {
            size1 = MIN_BUF_SIZE;
        }
        this._reset(new Uint8Array(size1), rd1);
    }
    size() {
        return this.buf.byteLength;
    }
    buffered() {
        return this.w - this.r;
    }
    async _fill() {
        if (this.r > 0) {
            this.buf.copyWithin(0, this.r, this.w);
            this.w -= this.r;
            this.r = 0;
        }
        if (this.w >= this.buf.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i1 = 100; i1 > 0; i1--){
            const rr = await this.rd.read(this.buf.subarray(this.w));
            if (rr === null) {
                this.eof = true;
                return;
            }
            assert(rr >= 0, "negative read");
            this.w += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    }
    reset(r) {
        this._reset(this.buf, r);
    }
    _reset(buf, rd) {
        this.buf = buf;
        this.rd = rd;
        this.eof = false;
    }
    async read(p) {
        let rr = p.byteLength;
        if (p.byteLength === 0) return rr;
        if (this.r === this.w) {
            if (p.byteLength >= this.buf.byteLength) {
                const rr1 = await this.rd.read(p);
                const nread = rr1 ?? 0;
                assert(nread >= 0, "negative read");
                return rr1;
            }
            this.r = 0;
            this.w = 0;
            rr = await this.rd.read(this.buf);
            if (rr === 0 || rr === null) return rr;
            assert(rr >= 0, "negative read");
            this.w += rr;
        }
        const copied = copy(this.buf.subarray(this.r, this.w), p, 0);
        this.r += copied;
        return copied;
    }
    async readFull(p) {
        let bytesRead = 0;
        while(bytesRead < p.length){
            try {
                const rr = await this.read(p.subarray(bytesRead));
                if (rr === null) {
                    if (bytesRead === 0) {
                        return null;
                    } else {
                        throw new PartialReadError();
                    }
                }
                bytesRead += rr;
            } catch (err) {
                err.partial = p.subarray(0, bytesRead);
                throw err;
            }
        }
        return p;
    }
    async readByte() {
        while(this.r === this.w){
            if (this.eof) return null;
            await this._fill();
        }
        const c = this.buf[this.r];
        this.r++;
        return c;
    }
    async readString(delim) {
        if (delim.length !== 1) {
            throw new Error("Delimiter should be a single character");
        }
        const buffer = await this.readSlice(delim.charCodeAt(0));
        if (buffer === null) return null;
        return new TextDecoder().decode(buffer);
    }
    async readLine() {
        let line;
        try {
            line = await this.readSlice(LF);
        } catch (err) {
            if (err instanceof Deno.errors.BadResource) {
                throw err;
            }
            let { partial: partial2  } = err;
            assert(partial2 instanceof Uint8Array, "bufio: caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError)) {
                throw err;
            }
            if (!this.eof && partial2.byteLength > 0 && partial2[partial2.byteLength - 1] === CR) {
                assert(this.r > 0, "bufio: tried to rewind past start of buffer");
                this.r--;
                partial2 = partial2.subarray(0, partial2.byteLength - 1);
            }
            return {
                line: partial2,
                more: !this.eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                line,
                more: false
            };
        }
        if (line[line.byteLength - 1] == LF) {
            let drop = 1;
            if (line.byteLength > 1 && line[line.byteLength - 2] === CR) {
                drop = 2;
            }
            line = line.subarray(0, line.byteLength - drop);
        }
        return {
            line,
            more: false
        };
    }
    async readSlice(delim) {
        let s = 0;
        let slice;
        while(true){
            let i1 = this.buf.subarray(this.r + s, this.w).indexOf(delim);
            if (i1 >= 0) {
                i1 += s;
                slice = this.buf.subarray(this.r, this.r + i1 + 1);
                this.r += i1 + 1;
                break;
            }
            if (this.eof) {
                if (this.r === this.w) {
                    return null;
                }
                slice = this.buf.subarray(this.r, this.w);
                this.r = this.w;
                break;
            }
            if (this.buffered() >= this.buf.byteLength) {
                this.r = this.w;
                const oldbuf = this.buf;
                const newbuf = this.buf.slice(0);
                this.buf = newbuf;
                throw new BufferFullError(oldbuf);
            }
            s = this.w - this.r;
            try {
                await this._fill();
            } catch (err) {
                err.partial = slice;
                throw err;
            }
        }
        return slice;
    }
    async peek(n) {
        if (n < 0) {
            throw Error("negative count");
        }
        let avail = this.w - this.r;
        while(avail < n && avail < this.buf.byteLength && !this.eof){
            try {
                await this._fill();
            } catch (err) {
                err.partial = this.buf.subarray(this.r, this.w);
                throw err;
            }
            avail = this.w - this.r;
        }
        if (avail === 0 && this.eof) {
            return null;
        } else if (avail < n && this.eof) {
            return this.buf.subarray(this.r, this.r + avail);
        } else if (avail < n) {
            throw new BufferFullError(this.buf.subarray(this.r, this.w));
        }
        return this.buf.subarray(this.r, this.r + n);
    }
}
class AbstractBufBase {
    buf;
    usedBufferBytes = 0;
    err = null;
    size() {
        return this.buf.byteLength;
    }
    available() {
        return this.buf.byteLength - this.usedBufferBytes;
    }
    buffered() {
        return this.usedBufferBytes;
    }
}
class BufWriter extends AbstractBufBase {
    writer;
    static create(writer, size = 4096) {
        return writer instanceof BufWriter ? writer : new BufWriter(writer, size);
    }
    constructor(writer1, size2 = 4096){
        super();
        this.writer = writer1;
        if (size2 <= 0) {
            size2 = DEFAULT_BUF_SIZE;
        }
        this.buf = new Uint8Array(size2);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    async flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            await writeAll(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    async write(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = await this.writer.write(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                await this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
}
class BufWriterSync extends AbstractBufBase {
    writer;
    static create(writer, size = 4096) {
        return writer instanceof BufWriterSync ? writer : new BufWriterSync(writer, size);
    }
    constructor(writer2, size3 = 4096){
        super();
        this.writer = writer2;
        if (size3 <= 0) {
            size3 = DEFAULT_BUF_SIZE;
        }
        this.buf = new Uint8Array(size3);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            writeAllSync(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    writeSync(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = this.writer.writeSync(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
}
const CHAR_SPACE = " ".charCodeAt(0);
const CHAR_TAB = "\t".charCodeAt(0);
const CHAR_COLON = ":".charCodeAt(0);
const WHITESPACES = [
    CHAR_SPACE,
    CHAR_TAB
];
const decoder = new TextDecoder();
const invalidHeaderCharRegex = /[^\t\x20-\x7e\x80-\xff]/g;
function str(buf) {
    return !buf ? "" : decoder.decode(buf);
}
class TextProtoReader {
    r;
    constructor(r1){
        this.r = r1;
    }
    async readLine() {
        const s = await this.readLineSlice();
        return s === null ? null : str(s);
    }
    async readMIMEHeader() {
        const m = new Headers();
        let line;
        let buf = await this.r.peek(1);
        if (buf === null) {
            return null;
        } else if (WHITESPACES.includes(buf[0])) {
            line = await this.readLineSlice();
        }
        buf = await this.r.peek(1);
        if (buf === null) {
            throw new Deno.errors.UnexpectedEof();
        } else if (WHITESPACES.includes(buf[0])) {
            throw new Deno.errors.InvalidData(`malformed MIME header initial line: ${str(line)}`);
        }
        while(true){
            const kv = await this.readLineSlice();
            if (kv === null) throw new Deno.errors.UnexpectedEof();
            if (kv.byteLength === 0) return m;
            let i1 = kv.indexOf(CHAR_COLON);
            if (i1 < 0) {
                throw new Deno.errors.InvalidData(`malformed MIME header line: ${str(kv)}`);
            }
            const key1 = str(kv.subarray(0, i1));
            if (key1 == "") {
                continue;
            }
            i1++;
            while(i1 < kv.byteLength && WHITESPACES.includes(kv[i1])){
                i1++;
            }
            const value2 = str(kv.subarray(i1)).replace(invalidHeaderCharRegex, encodeURI);
            try {
                m.append(key1, value2);
            } catch  {
            }
        }
    }
    async readLineSlice() {
        let line = new Uint8Array(0);
        let r1 = null;
        do {
            r1 = await this.r.readLine();
            if (r1 !== null && this.skipSpace(r1.line) !== 0) {
                line = concat(line, r1.line);
            }
        }while (r1 !== null && r1.more)
        return r1 === null ? null : line;
    }
    skipSpace(l) {
        let n = 0;
        for (const val of l){
            if (!WHITESPACES.includes(val)) {
                n++;
            }
        }
        return n;
    }
}
var Status;
(function(Status1) {
    Status1[Status1["Continue"] = 100] = "Continue";
    Status1[Status1["SwitchingProtocols"] = 101] = "SwitchingProtocols";
    Status1[Status1["Processing"] = 102] = "Processing";
    Status1[Status1["EarlyHints"] = 103] = "EarlyHints";
    Status1[Status1["OK"] = 200] = "OK";
    Status1[Status1["Created"] = 201] = "Created";
    Status1[Status1["Accepted"] = 202] = "Accepted";
    Status1[Status1["NonAuthoritativeInfo"] = 203] = "NonAuthoritativeInfo";
    Status1[Status1["NoContent"] = 204] = "NoContent";
    Status1[Status1["ResetContent"] = 205] = "ResetContent";
    Status1[Status1["PartialContent"] = 206] = "PartialContent";
    Status1[Status1["MultiStatus"] = 207] = "MultiStatus";
    Status1[Status1["AlreadyReported"] = 208] = "AlreadyReported";
    Status1[Status1["IMUsed"] = 226] = "IMUsed";
    Status1[Status1["MultipleChoices"] = 300] = "MultipleChoices";
    Status1[Status1["MovedPermanently"] = 301] = "MovedPermanently";
    Status1[Status1["Found"] = 302] = "Found";
    Status1[Status1["SeeOther"] = 303] = "SeeOther";
    Status1[Status1["NotModified"] = 304] = "NotModified";
    Status1[Status1["UseProxy"] = 305] = "UseProxy";
    Status1[Status1["TemporaryRedirect"] = 307] = "TemporaryRedirect";
    Status1[Status1["PermanentRedirect"] = 308] = "PermanentRedirect";
    Status1[Status1["BadRequest"] = 400] = "BadRequest";
    Status1[Status1["Unauthorized"] = 401] = "Unauthorized";
    Status1[Status1["PaymentRequired"] = 402] = "PaymentRequired";
    Status1[Status1["Forbidden"] = 403] = "Forbidden";
    Status1[Status1["NotFound"] = 404] = "NotFound";
    Status1[Status1["MethodNotAllowed"] = 405] = "MethodNotAllowed";
    Status1[Status1["NotAcceptable"] = 406] = "NotAcceptable";
    Status1[Status1["ProxyAuthRequired"] = 407] = "ProxyAuthRequired";
    Status1[Status1["RequestTimeout"] = 408] = "RequestTimeout";
    Status1[Status1["Conflict"] = 409] = "Conflict";
    Status1[Status1["Gone"] = 410] = "Gone";
    Status1[Status1["LengthRequired"] = 411] = "LengthRequired";
    Status1[Status1["PreconditionFailed"] = 412] = "PreconditionFailed";
    Status1[Status1["RequestEntityTooLarge"] = 413] = "RequestEntityTooLarge";
    Status1[Status1["RequestURITooLong"] = 414] = "RequestURITooLong";
    Status1[Status1["UnsupportedMediaType"] = 415] = "UnsupportedMediaType";
    Status1[Status1["RequestedRangeNotSatisfiable"] = 416] = "RequestedRangeNotSatisfiable";
    Status1[Status1["ExpectationFailed"] = 417] = "ExpectationFailed";
    Status1[Status1["Teapot"] = 418] = "Teapot";
    Status1[Status1["MisdirectedRequest"] = 421] = "MisdirectedRequest";
    Status1[Status1["UnprocessableEntity"] = 422] = "UnprocessableEntity";
    Status1[Status1["Locked"] = 423] = "Locked";
    Status1[Status1["FailedDependency"] = 424] = "FailedDependency";
    Status1[Status1["TooEarly"] = 425] = "TooEarly";
    Status1[Status1["UpgradeRequired"] = 426] = "UpgradeRequired";
    Status1[Status1["PreconditionRequired"] = 428] = "PreconditionRequired";
    Status1[Status1["TooManyRequests"] = 429] = "TooManyRequests";
    Status1[Status1["RequestHeaderFieldsTooLarge"] = 431] = "RequestHeaderFieldsTooLarge";
    Status1[Status1["UnavailableForLegalReasons"] = 451] = "UnavailableForLegalReasons";
    Status1[Status1["InternalServerError"] = 500] = "InternalServerError";
    Status1[Status1["NotImplemented"] = 501] = "NotImplemented";
    Status1[Status1["BadGateway"] = 502] = "BadGateway";
    Status1[Status1["ServiceUnavailable"] = 503] = "ServiceUnavailable";
    Status1[Status1["GatewayTimeout"] = 504] = "GatewayTimeout";
    Status1[Status1["HTTPVersionNotSupported"] = 505] = "HTTPVersionNotSupported";
    Status1[Status1["VariantAlsoNegotiates"] = 506] = "VariantAlsoNegotiates";
    Status1[Status1["InsufficientStorage"] = 507] = "InsufficientStorage";
    Status1[Status1["LoopDetected"] = 508] = "LoopDetected";
    Status1[Status1["NotExtended"] = 510] = "NotExtended";
    Status1[Status1["NetworkAuthenticationRequired"] = 511] = "NetworkAuthenticationRequired";
})(Status || (Status = {
}));
const STATUS_TEXT = new Map([
    [
        Status.Continue,
        "Continue"
    ],
    [
        Status.SwitchingProtocols,
        "Switching Protocols"
    ],
    [
        Status.Processing,
        "Processing"
    ],
    [
        Status.EarlyHints,
        "Early Hints"
    ],
    [
        Status.OK,
        "OK"
    ],
    [
        Status.Created,
        "Created"
    ],
    [
        Status.Accepted,
        "Accepted"
    ],
    [
        Status.NonAuthoritativeInfo,
        "Non-Authoritative Information"
    ],
    [
        Status.NoContent,
        "No Content"
    ],
    [
        Status.ResetContent,
        "Reset Content"
    ],
    [
        Status.PartialContent,
        "Partial Content"
    ],
    [
        Status.MultiStatus,
        "Multi-Status"
    ],
    [
        Status.AlreadyReported,
        "Already Reported"
    ],
    [
        Status.IMUsed,
        "IM Used"
    ],
    [
        Status.MultipleChoices,
        "Multiple Choices"
    ],
    [
        Status.MovedPermanently,
        "Moved Permanently"
    ],
    [
        Status.Found,
        "Found"
    ],
    [
        Status.SeeOther,
        "See Other"
    ],
    [
        Status.NotModified,
        "Not Modified"
    ],
    [
        Status.UseProxy,
        "Use Proxy"
    ],
    [
        Status.TemporaryRedirect,
        "Temporary Redirect"
    ],
    [
        Status.PermanentRedirect,
        "Permanent Redirect"
    ],
    [
        Status.BadRequest,
        "Bad Request"
    ],
    [
        Status.Unauthorized,
        "Unauthorized"
    ],
    [
        Status.PaymentRequired,
        "Payment Required"
    ],
    [
        Status.Forbidden,
        "Forbidden"
    ],
    [
        Status.NotFound,
        "Not Found"
    ],
    [
        Status.MethodNotAllowed,
        "Method Not Allowed"
    ],
    [
        Status.NotAcceptable,
        "Not Acceptable"
    ],
    [
        Status.ProxyAuthRequired,
        "Proxy Authentication Required"
    ],
    [
        Status.RequestTimeout,
        "Request Timeout"
    ],
    [
        Status.Conflict,
        "Conflict"
    ],
    [
        Status.Gone,
        "Gone"
    ],
    [
        Status.LengthRequired,
        "Length Required"
    ],
    [
        Status.PreconditionFailed,
        "Precondition Failed"
    ],
    [
        Status.RequestEntityTooLarge,
        "Request Entity Too Large"
    ],
    [
        Status.RequestURITooLong,
        "Request URI Too Long"
    ],
    [
        Status.UnsupportedMediaType,
        "Unsupported Media Type"
    ],
    [
        Status.RequestedRangeNotSatisfiable,
        "Requested Range Not Satisfiable"
    ],
    [
        Status.ExpectationFailed,
        "Expectation Failed"
    ],
    [
        Status.Teapot,
        "I'm a teapot"
    ],
    [
        Status.MisdirectedRequest,
        "Misdirected Request"
    ],
    [
        Status.UnprocessableEntity,
        "Unprocessable Entity"
    ],
    [
        Status.Locked,
        "Locked"
    ],
    [
        Status.FailedDependency,
        "Failed Dependency"
    ],
    [
        Status.TooEarly,
        "Too Early"
    ],
    [
        Status.UpgradeRequired,
        "Upgrade Required"
    ],
    [
        Status.PreconditionRequired,
        "Precondition Required"
    ],
    [
        Status.TooManyRequests,
        "Too Many Requests"
    ],
    [
        Status.RequestHeaderFieldsTooLarge,
        "Request Header Fields Too Large"
    ],
    [
        Status.UnavailableForLegalReasons,
        "Unavailable For Legal Reasons"
    ],
    [
        Status.InternalServerError,
        "Internal Server Error"
    ],
    [
        Status.NotImplemented,
        "Not Implemented"
    ],
    [
        Status.BadGateway,
        "Bad Gateway"
    ],
    [
        Status.ServiceUnavailable,
        "Service Unavailable"
    ],
    [
        Status.GatewayTimeout,
        "Gateway Timeout"
    ],
    [
        Status.HTTPVersionNotSupported,
        "HTTP Version Not Supported"
    ],
    [
        Status.VariantAlsoNegotiates,
        "Variant Also Negotiates"
    ],
    [
        Status.InsufficientStorage,
        "Insufficient Storage"
    ],
    [
        Status.LoopDetected,
        "Loop Detected"
    ],
    [
        Status.NotExtended,
        "Not Extended"
    ],
    [
        Status.NetworkAuthenticationRequired,
        "Network Authentication Required"
    ], 
]);
function deferred() {
    let methods;
    const promise = new Promise((resolve, reject)=>{
        methods = {
            resolve,
            reject
        };
    });
    return Object.assign(promise, methods);
}
class MuxAsyncIterator {
    iteratorCount = 0;
    yields = [];
    throws = [];
    signal = deferred();
    add(iterable) {
        ++this.iteratorCount;
        this.callIteratorNext(iterable[Symbol.asyncIterator]());
    }
    async callIteratorNext(iterator) {
        try {
            const { value: value2 , done  } = await iterator.next();
            if (done) {
                --this.iteratorCount;
            } else {
                this.yields.push({
                    iterator,
                    value: value2
                });
            }
        } catch (e) {
            this.throws.push(e);
        }
        this.signal.resolve();
    }
    async *iterate() {
        while(this.iteratorCount > 0){
            await this.signal;
            for(let i1 = 0; i1 < this.yields.length; i1++){
                const { iterator , value: value2  } = this.yields[i1];
                yield value2;
                this.callIteratorNext(iterator);
            }
            if (this.throws.length) {
                for (const e of this.throws){
                    throw e;
                }
                this.throws.length = 0;
            }
            this.yields.length = 0;
            this.signal = deferred();
        }
    }
    [Symbol.asyncIterator]() {
        return this.iterate();
    }
}
const noop = ()=>{
};
class AsyncIterableClone {
    currentPromise;
    resolveCurrent = noop;
    consumed;
    consume = noop;
    constructor(){
        this.currentPromise = new Promise((resolve)=>{
            this.resolveCurrent = resolve;
        });
        this.consumed = new Promise((resolve)=>{
            this.consume = resolve;
        });
    }
    reset() {
        this.currentPromise = new Promise((resolve)=>{
            this.resolveCurrent = resolve;
        });
        this.consumed = new Promise((resolve)=>{
            this.consume = resolve;
        });
    }
    async next() {
        const res = await this.currentPromise;
        this.consume();
        this.reset();
        return res;
    }
    async push(res) {
        this.resolveCurrent(res);
        await this.consumed;
    }
    [Symbol.asyncIterator]() {
        return this;
    }
}
class DeadlineError extends Error {
    constructor(){
        super("Deadline");
        this.name = "DeadlineError";
    }
}
const encoder = new TextEncoder();
function emptyReader() {
    return {
        read (_) {
            return Promise.resolve(null);
        }
    };
}
function bodyReader(contentLength, r1) {
    let totalRead = 0;
    let finished = false;
    async function read(buf) {
        if (finished) return null;
        let result;
        const remaining = contentLength - totalRead;
        if (remaining >= buf.byteLength) {
            result = await r1.read(buf);
        } else {
            const readBuf = buf.subarray(0, remaining);
            result = await r1.read(readBuf);
        }
        if (result !== null) {
            totalRead += result;
        }
        finished = totalRead === contentLength;
        return result;
    }
    return {
        read
    };
}
function chunkedBodyReader(h, r1) {
    const tp = new TextProtoReader(r1);
    let finished = false;
    const chunks = [];
    async function read(buf) {
        if (finished) return null;
        const [chunk] = chunks;
        if (chunk) {
            const chunkRemaining = chunk.data.byteLength - chunk.offset;
            const readLength = Math.min(chunkRemaining, buf.byteLength);
            for(let i1 = 0; i1 < readLength; i1++){
                buf[i1] = chunk.data[chunk.offset + i1];
            }
            chunk.offset += readLength;
            if (chunk.offset === chunk.data.byteLength) {
                chunks.shift();
                if (await tp.readLine() === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
            }
            return readLength;
        }
        const line = await tp.readLine();
        if (line === null) throw new Deno.errors.UnexpectedEof();
        const [chunkSizeString] = line.split(";");
        const chunkSize = parseInt(chunkSizeString, 16);
        if (Number.isNaN(chunkSize) || chunkSize < 0) {
            throw new Deno.errors.InvalidData("Invalid chunk size");
        }
        if (chunkSize > 0) {
            if (chunkSize > buf.byteLength) {
                let eof = await r1.readFull(buf);
                if (eof === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
                const restChunk = new Uint8Array(chunkSize - buf.byteLength);
                eof = await r1.readFull(restChunk);
                if (eof === null) {
                    throw new Deno.errors.UnexpectedEof();
                } else {
                    chunks.push({
                        offset: 0,
                        data: restChunk
                    });
                }
                return buf.byteLength;
            } else {
                const bufToFill = buf.subarray(0, chunkSize);
                const eof = await r1.readFull(bufToFill);
                if (eof === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
                if (await tp.readLine() === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
                return chunkSize;
            }
        } else {
            assert(chunkSize === 0);
            if (await r1.readLine() === null) {
                throw new Deno.errors.UnexpectedEof();
            }
            await readTrailers(h, r1);
            finished = true;
            return null;
        }
    }
    return {
        read
    };
}
function isProhibidedForTrailer(key1) {
    const s = new Set([
        "transfer-encoding",
        "content-length",
        "trailer"
    ]);
    return s.has(key1.toLowerCase());
}
async function readTrailers(headers, r1) {
    const trailers = parseTrailer(headers.get("trailer"));
    if (trailers == null) return;
    const trailerNames = [
        ...trailers.keys()
    ];
    const tp = new TextProtoReader(r1);
    const result = await tp.readMIMEHeader();
    if (result == null) {
        throw new Deno.errors.InvalidData("Missing trailer header.");
    }
    const undeclared = [
        ...result.keys()
    ].filter((k)=>!trailerNames.includes(k)
    );
    if (undeclared.length > 0) {
        throw new Deno.errors.InvalidData(`Undeclared trailers: ${Deno.inspect(undeclared)}.`);
    }
    for (const [k, v] of result){
        headers.append(k, v);
    }
    const missingTrailers = trailerNames.filter((k1)=>!result.has(k1)
    );
    if (missingTrailers.length > 0) {
        throw new Deno.errors.InvalidData(`Missing trailers: ${Deno.inspect(missingTrailers)}.`);
    }
    headers.delete("trailer");
}
function parseTrailer(field) {
    if (field == null) {
        return undefined;
    }
    const trailerNames = field.split(",").map((v)=>v.trim().toLowerCase()
    );
    if (trailerNames.length === 0) {
        throw new Deno.errors.InvalidData("Empty trailer header.");
    }
    const prohibited = trailerNames.filter((k)=>isProhibidedForTrailer(k)
    );
    if (prohibited.length > 0) {
        throw new Deno.errors.InvalidData(`Prohibited trailer names: ${Deno.inspect(prohibited)}.`);
    }
    return new Headers(trailerNames.map((key1)=>[
            key1,
            ""
        ]
    ));
}
async function writeChunkedBody(w, r1) {
    for await (const chunk of iter(r1)){
        if (chunk.byteLength <= 0) continue;
        const start = encoder.encode(`${chunk.byteLength.toString(16)}\r\n`);
        const end = encoder.encode("\r\n");
        await w.write(start);
        await w.write(chunk);
        await w.write(end);
        await w.flush();
    }
    const endChunk = encoder.encode("0\r\n\r\n");
    await w.write(endChunk);
}
async function writeTrailers(w, headers, trailers) {
    const trailer = headers.get("trailer");
    if (trailer === null) {
        throw new TypeError("Missing trailer header.");
    }
    const transferEncoding = headers.get("transfer-encoding");
    if (transferEncoding === null || !transferEncoding.match(/^chunked/)) {
        throw new TypeError(`Trailers are only allowed for "transfer-encoding: chunked", got "transfer-encoding: ${transferEncoding}".`);
    }
    const writer3 = BufWriter.create(w);
    const trailerNames = trailer.split(",").map((s)=>s.trim().toLowerCase()
    );
    const prohibitedTrailers = trailerNames.filter((k)=>isProhibidedForTrailer(k)
    );
    if (prohibitedTrailers.length > 0) {
        throw new TypeError(`Prohibited trailer names: ${Deno.inspect(prohibitedTrailers)}.`);
    }
    const undeclared = [
        ...trailers.keys()
    ].filter((k)=>!trailerNames.includes(k)
    );
    if (undeclared.length > 0) {
        throw new TypeError(`Undeclared trailers: ${Deno.inspect(undeclared)}.`);
    }
    for (const [key1, value2] of trailers){
        await writer3.write(encoder.encode(`${key1}: ${value2}\r\n`));
    }
    await writer3.write(encoder.encode("\r\n"));
    await writer3.flush();
}
async function writeResponse(w, r1) {
    const protoMajor = 1;
    const protoMinor = 1;
    const statusCode = r1.status || 200;
    const statusText = (r1.statusText ?? STATUS_TEXT.get(statusCode)) ?? null;
    const writer3 = BufWriter.create(w);
    if (statusText === null) {
        throw new Deno.errors.InvalidData("Empty statusText (explicitely pass an empty string if this was intentional)");
    }
    if (!r1.body) {
        r1.body = new Uint8Array();
    }
    if (typeof r1.body === "string") {
        r1.body = encoder.encode(r1.body);
    }
    let out = `HTTP/${1}.${1} ${statusCode} ${statusText}\r\n`;
    const headers = r1.headers ?? new Headers();
    if (r1.body && !headers.get("content-length")) {
        if (r1.body instanceof Uint8Array) {
            out += `content-length: ${r1.body.byteLength}\r\n`;
        } else if (!headers.get("transfer-encoding")) {
            out += "transfer-encoding: chunked\r\n";
        }
    }
    for (const [key1, value2] of headers){
        out += `${key1}: ${value2}\r\n`;
    }
    out += `\r\n`;
    const header = encoder.encode(out);
    const n = await writer3.write(header);
    assert(n === header.byteLength);
    if (r1.body instanceof Uint8Array) {
        const n1 = await writer3.write(r1.body);
        assert(n1 === r1.body.byteLength);
    } else if (headers.has("content-length")) {
        const contentLength = headers.get("content-length");
        assert(contentLength != null);
        const bodyLength = parseInt(contentLength);
        const n1 = await copy1(r1.body, writer3);
        assert(n1 === bodyLength);
    } else {
        await writeChunkedBody(writer3, r1.body);
    }
    if (r1.trailers) {
        const t = await r1.trailers();
        await writeTrailers(writer3, headers, t);
    }
    await writer3.flush();
}
class ServerRequest {
    url;
    method;
    proto;
    protoMinor;
    protoMajor;
    headers;
    conn;
    r;
    w;
    #done = deferred();
    #contentLength = undefined;
    #body = undefined;
    #finalized = false;
    get done() {
        return this.#done.then((e)=>e
        );
    }
    get contentLength() {
        if (this.#contentLength === undefined) {
            const cl = this.headers.get("content-length");
            if (cl) {
                this.#contentLength = parseInt(cl);
                if (Number.isNaN(this.#contentLength)) {
                    this.#contentLength = null;
                }
            } else {
                this.#contentLength = null;
            }
        }
        return this.#contentLength;
    }
    get body() {
        if (!this.#body) {
            if (this.contentLength != null) {
                this.#body = bodyReader(this.contentLength, this.r);
            } else {
                const transferEncoding = this.headers.get("transfer-encoding");
                if (transferEncoding != null) {
                    const parts = transferEncoding.split(",").map((e)=>e.trim().toLowerCase()
                    );
                    assert(parts.includes("chunked"), 'transfer-encoding must include "chunked" if content-length is not set');
                    this.#body = chunkedBodyReader(this.headers, this.r);
                } else {
                    this.#body = emptyReader();
                }
            }
        }
        return this.#body;
    }
    async respond(r) {
        let err;
        try {
            await writeResponse(this.w, r);
        } catch (e) {
            try {
                this.conn.close();
            } catch  {
            }
            err = e;
        }
        this.#done.resolve(err);
        if (err) {
            throw err;
        }
    }
    async finalize() {
        if (this.#finalized) return;
        const body = this.body;
        const buf = new Uint8Array(1024);
        while(await body.read(buf) !== null){
        }
        this.#finalized = true;
    }
}
function parseHTTPVersion(vers) {
    switch(vers){
        case "HTTP/1.1":
            return [
                1,
                1
            ];
        case "HTTP/1.0":
            return [
                1,
                0
            ];
        default:
            {
                const Big = 1000000;
                if (!vers.startsWith("HTTP/")) {
                    break;
                }
                const dot = vers.indexOf(".");
                if (dot < 0) {
                    break;
                }
                const majorStr = vers.substring(vers.indexOf("/") + 1, dot);
                const major = Number(majorStr);
                if (!Number.isInteger(major) || major < 0 || major > 1000000) {
                    break;
                }
                const minorStr = vers.substring(dot + 1);
                const minor = Number(minorStr);
                if (!Number.isInteger(minor) || minor < 0 || minor > 1000000) {
                    break;
                }
                return [
                    major,
                    minor
                ];
            }
    }
    throw new Error(`malformed HTTP version ${vers}`);
}
async function readRequest(conn, bufr) {
    const tp = new TextProtoReader(bufr);
    const firstLine = await tp.readLine();
    if (firstLine === null) return null;
    const headers = await tp.readMIMEHeader();
    if (headers === null) throw new Deno.errors.UnexpectedEof();
    const req = new ServerRequest();
    req.conn = conn;
    req.r = bufr;
    [req.method, req.url, req.proto] = firstLine.split(" ", 3);
    [req.protoMajor, req.protoMinor] = parseHTTPVersion(req.proto);
    req.headers = headers;
    fixLength(req);
    return req;
}
class Server {
    listener;
    #closing = false;
    #connections = [];
    constructor(listener1){
        this.listener = listener1;
    }
    close() {
        this.#closing = true;
        this.listener.close();
        for (const conn of this.#connections){
            try {
                conn.close();
            } catch (e) {
                if (!(e instanceof Deno.errors.BadResource)) {
                    throw e;
                }
            }
        }
    }
    async *iterateHttpRequests(conn) {
        const reader = new BufReader(conn);
        const writer3 = new BufWriter(conn);
        while(!this.#closing){
            let request1;
            try {
                request1 = await readRequest(conn, reader);
            } catch (error) {
                if (error instanceof Deno.errors.InvalidData || error instanceof Deno.errors.UnexpectedEof) {
                    try {
                        await writeResponse(writer3, {
                            status: 400,
                            body: new TextEncoder().encode(`${error.message}\r\n\r\n`)
                        });
                    } catch  {
                    }
                }
                break;
            }
            if (request1 === null) {
                break;
            }
            request1.w = writer3;
            yield request1;
            const responseError = await request1.done;
            if (responseError) {
                this.untrackConnection(request1.conn);
                return;
            }
            try {
                await request1.finalize();
            } catch  {
                break;
            }
        }
        this.untrackConnection(conn);
        try {
            conn.close();
        } catch  {
        }
    }
    trackConnection(conn) {
        this.#connections.push(conn);
    }
    untrackConnection(conn) {
        const index = this.#connections.indexOf(conn);
        if (index !== -1) {
            this.#connections.splice(index, 1);
        }
    }
    async *acceptConnAndIterateHttpRequests(mux) {
        if (this.#closing) return;
        let conn;
        try {
            conn = await this.listener.accept();
        } catch (error) {
            if (error instanceof Deno.errors.BadResource || error instanceof Deno.errors.InvalidData || error instanceof Deno.errors.UnexpectedEof || error instanceof Deno.errors.ConnectionReset || error instanceof Deno.errors.NotConnected) {
                return mux.add(this.acceptConnAndIterateHttpRequests(mux));
            }
            throw error;
        }
        this.trackConnection(conn);
        mux.add(this.acceptConnAndIterateHttpRequests(mux));
        yield* this.iterateHttpRequests(conn);
    }
    [Symbol.asyncIterator]() {
        const mux = new MuxAsyncIterator();
        mux.add(this.acceptConnAndIterateHttpRequests(mux));
        return mux.iterate();
    }
}
function _parseAddrFromStr(addr) {
    let url;
    try {
        const host = addr.startsWith(":") ? `0.0.0.0${addr}` : addr;
        url = new URL(`http://${host}`);
    } catch  {
        throw new TypeError("Invalid address.");
    }
    if (url.username || url.password || url.pathname != "/" || url.search || url.hash) {
        throw new TypeError("Invalid address.");
    }
    return {
        hostname: url.hostname,
        port: url.port === "" ? 80 : Number(url.port)
    };
}
function serve(addr) {
    if (typeof addr === "string") {
        addr = _parseAddrFromStr(addr);
    }
    const listener1 = Deno.listen(addr);
    return new Server(listener1);
}
function serveTLS(options2) {
    const tlsOptions = {
        ...options2,
        transport: "tcp"
    };
    const listener1 = Deno.listenTls(tlsOptions);
    return new Server(listener1);
}
function fixLength(req) {
    const contentLength = req.headers.get("Content-Length");
    if (contentLength) {
        const arrClen = contentLength.split(",");
        if (arrClen.length > 1) {
            const distinct = [
                ...new Set(arrClen.map((e)=>e.trim()
                ))
            ];
            if (distinct.length > 1) {
                throw Error("cannot contain multiple Content-Length headers");
            } else {
                req.headers.set("Content-Length", distinct[0]);
            }
        }
        const c = req.headers.get("Content-Length");
        if (req.method === "HEAD" && c && c !== "0") {
            throw Error("http: method cannot contain a Content-Length");
        }
        if (c && req.headers.has("transfer-encoding")) {
            throw new Error("http: Transfer-Encoding and Content-Length cannot be send together");
        }
    }
}
class StringReader extends Buffer {
    constructor(s){
        super(new TextEncoder().encode(s).buffer);
    }
}
class MultiReader {
    readers;
    currentIndex = 0;
    constructor(...readers){
        this.readers = readers;
    }
    async read(p) {
        const r2 = this.readers[this.currentIndex];
        if (!r2) return null;
        const result = await r2.read(p);
        if (result === null) {
            this.currentIndex++;
            return 0;
        }
        return result;
    }
}
class LimitedReader {
    reader;
    limit;
    constructor(reader1, limit){
        this.reader = reader1;
        this.limit = limit;
    }
    async read(p) {
        if (this.limit <= 0) {
            return null;
        }
        if (p.length > this.limit) {
            p = p.subarray(0, this.limit);
        }
        const n = await this.reader.read(p);
        if (n == null) {
            return null;
        }
        this.limit -= n;
        return n;
    }
}
function readerFromStreamReader(streamReader) {
    const buffer = new Buffer();
    return {
        async read (p) {
            if (buffer.empty()) {
                const res = await streamReader.read();
                if (res.done) {
                    return null;
                }
                await writeAll(buffer, res.value);
            }
            return buffer.read(p);
        }
    };
}
const osType = (()=>{
    const { Deno  } = globalThis;
    if (typeof Deno?.build?.os === "string") {
        return Deno.build.os;
    }
    const { navigator  } = globalThis;
    if (navigator?.appVersion?.includes?.("Win") ?? false) {
        return "windows";
    }
    return "linux";
})();
const isWindows = osType === "windows";
const CHAR_FORWARD_SLASH = 47;
function assertPath(path) {
    if (typeof path !== "string") {
        throw new TypeError(`Path must be a string. Received ${JSON.stringify(path)}`);
    }
}
function isPosixPathSeparator(code) {
    return code === 47;
}
function isPathSeparator(code) {
    return isPosixPathSeparator(code) || code === 92;
}
function isWindowsDeviceRoot(code) {
    return code >= 97 && code <= 122 || code >= 65 && code <= 90;
}
function normalizeString(path, allowAboveRoot, separator, isPathSeparator1) {
    let res = "";
    let lastSegmentLength = 0;
    let lastSlash = -1;
    let dots = 0;
    let code;
    for(let i1 = 0, len = path.length; i1 <= len; ++i1){
        if (i1 < len) code = path.charCodeAt(i1);
        else if (isPathSeparator1(code)) break;
        else code = CHAR_FORWARD_SLASH;
        if (isPathSeparator1(code)) {
            if (lastSlash === i1 - 1 || dots === 1) {
            } else if (lastSlash !== i1 - 1 && dots === 2) {
                if (res.length < 2 || lastSegmentLength !== 2 || res.charCodeAt(res.length - 1) !== 46 || res.charCodeAt(res.length - 2) !== 46) {
                    if (res.length > 2) {
                        const lastSlashIndex = res.lastIndexOf(separator);
                        if (lastSlashIndex === -1) {
                            res = "";
                            lastSegmentLength = 0;
                        } else {
                            res = res.slice(0, lastSlashIndex);
                            lastSegmentLength = res.length - 1 - res.lastIndexOf(separator);
                        }
                        lastSlash = i1;
                        dots = 0;
                        continue;
                    } else if (res.length === 2 || res.length === 1) {
                        res = "";
                        lastSegmentLength = 0;
                        lastSlash = i1;
                        dots = 0;
                        continue;
                    }
                }
                if (allowAboveRoot) {
                    if (res.length > 0) res += `${separator}..`;
                    else res = "..";
                    lastSegmentLength = 2;
                }
            } else {
                if (res.length > 0) res += separator + path.slice(lastSlash + 1, i1);
                else res = path.slice(lastSlash + 1, i1);
                lastSegmentLength = i1 - lastSlash - 1;
            }
            lastSlash = i1;
            dots = 0;
        } else if (code === 46 && dots !== -1) {
            ++dots;
        } else {
            dots = -1;
        }
    }
    return res;
}
function _format(sep, pathObject) {
    const dir = pathObject.dir || pathObject.root;
    const base = pathObject.base || (pathObject.name || "") + (pathObject.ext || "");
    if (!dir) return base;
    if (dir === pathObject.root) return dir + base;
    return dir + sep + base;
}
const WHITESPACE_ENCODINGS = {
    "\u0009": "%09",
    "\u000A": "%0A",
    "\u000B": "%0B",
    "\u000C": "%0C",
    "\u000D": "%0D",
    "\u0020": "%20"
};
function encodeWhitespace(string) {
    return string.replaceAll(/[\s]/g, (c)=>{
        return WHITESPACE_ENCODINGS[c] ?? c;
    });
}
const sep = "\\";
const delimiter = ";";
function resolve(...pathSegments) {
    let resolvedDevice = "";
    let resolvedTail = "";
    let resolvedAbsolute = false;
    for(let i1 = pathSegments.length - 1; i1 >= -1; i1--){
        let path;
        const { Deno  } = globalThis;
        if (i1 >= 0) {
            path = pathSegments[i1];
        } else if (!resolvedDevice) {
            if (typeof Deno?.cwd !== "function") {
                throw new TypeError("Resolved a drive-letter-less path without a CWD.");
            }
            path = Deno.cwd();
        } else {
            if (typeof Deno?.env?.get !== "function" || typeof Deno?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno.env.get(`=${resolvedDevice}`) || Deno.cwd();
            if (path === undefined || path.slice(0, 3).toLowerCase() !== `${resolvedDevice.toLowerCase()}\\`) {
                path = `${resolvedDevice}\\`;
            }
        }
        assertPath(path);
        const len = path.length;
        if (len === 0) continue;
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator(code)) {
                isAbsolute = true;
                if (isPathSeparator(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        const firstPart = path.slice(last, j);
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                device = `\\\\${firstPart}\\${path.slice(last)}`;
                                rootEnd = j;
                            } else if (j !== last) {
                                device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                                rootEnd = j;
                            }
                        }
                    }
                } else {
                    rootEnd = 1;
                }
            } else if (isWindowsDeviceRoot(code)) {
                if (path.charCodeAt(1) === 58) {
                    device = path.slice(0, 2);
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator(path.charCodeAt(2))) {
                            isAbsolute = true;
                            rootEnd = 3;
                        }
                    }
                }
            }
        } else if (isPathSeparator(code)) {
            rootEnd = 1;
            isAbsolute = true;
        }
        if (device.length > 0 && resolvedDevice.length > 0 && device.toLowerCase() !== resolvedDevice.toLowerCase()) {
            continue;
        }
        if (resolvedDevice.length === 0 && device.length > 0) {
            resolvedDevice = device;
        }
        if (!resolvedAbsolute) {
            resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
            resolvedAbsolute = isAbsolute;
        }
        if (resolvedAbsolute && resolvedDevice.length > 0) break;
    }
    resolvedTail = normalizeString(resolvedTail, !resolvedAbsolute, "\\", isPathSeparator);
    return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail || ".";
}
function normalize(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = 0;
    let device;
    let isAbsolute = false;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            isAbsolute = true;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    const firstPart = path.slice(last, j);
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return `\\\\${firstPart}\\${path.slice(last)}\\`;
                        } else if (j !== last) {
                            device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                            rootEnd = j;
                        }
                    }
                }
            } else {
                rootEnd = 1;
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                device = path.slice(0, 2);
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) {
                        isAbsolute = true;
                        rootEnd = 3;
                    }
                }
            }
        }
    } else if (isPathSeparator(code)) {
        return "\\";
    }
    let tail;
    if (rootEnd < len) {
        tail = normalizeString(path.slice(rootEnd), !isAbsolute, "\\", isPathSeparator);
    } else {
        tail = "";
    }
    if (tail.length === 0 && !isAbsolute) tail = ".";
    if (tail.length > 0 && isPathSeparator(path.charCodeAt(len - 1))) {
        tail += "\\";
    }
    if (device === undefined) {
        if (isAbsolute) {
            if (tail.length > 0) return `\\${tail}`;
            else return "\\";
        } else if (tail.length > 0) {
            return tail;
        } else {
            return "";
        }
    } else if (isAbsolute) {
        if (tail.length > 0) return `${device}\\${tail}`;
        else return `${device}\\`;
    } else if (tail.length > 0) {
        return device + tail;
    } else {
        return device;
    }
}
function isAbsolute(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return false;
    const code = path.charCodeAt(0);
    if (isPathSeparator(code)) {
        return true;
    } else if (isWindowsDeviceRoot(code)) {
        if (len > 2 && path.charCodeAt(1) === 58) {
            if (isPathSeparator(path.charCodeAt(2))) return true;
        }
    }
    return false;
}
function join(...paths) {
    const pathsCount = paths.length;
    if (pathsCount === 0) return ".";
    let joined;
    let firstPart = null;
    for(let i1 = 0; i1 < pathsCount; ++i1){
        const path = paths[i1];
        assertPath(path);
        if (path.length > 0) {
            if (joined === undefined) joined = firstPart = path;
            else joined += `\\${path}`;
        }
    }
    if (joined === undefined) return ".";
    let needsReplace = true;
    let slashCount = 0;
    assert(firstPart != null);
    if (isPathSeparator(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
            if (isPathSeparator(firstPart.charCodeAt(1))) {
                ++slashCount;
                if (firstLen > 2) {
                    if (isPathSeparator(firstPart.charCodeAt(2))) ++slashCount;
                    else {
                        needsReplace = false;
                    }
                }
            }
        }
    }
    if (needsReplace) {
        for(; slashCount < joined.length; ++slashCount){
            if (!isPathSeparator(joined.charCodeAt(slashCount))) break;
        }
        if (slashCount >= 2) joined = `\\${joined.slice(slashCount)}`;
    }
    return normalize(joined);
}
function relative(from, to) {
    assertPath(from);
    assertPath(to);
    if (from === to) return "";
    const fromOrig = resolve(from);
    const toOrig = resolve(to);
    if (fromOrig === toOrig) return "";
    from = fromOrig.toLowerCase();
    to = toOrig.toLowerCase();
    if (from === to) return "";
    let fromStart = 0;
    let fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (from.charCodeAt(fromStart) !== 92) break;
    }
    for(; fromEnd - 1 > fromStart; --fromEnd){
        if (from.charCodeAt(fromEnd - 1) !== 92) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 0;
    let toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (to.charCodeAt(toStart) !== 92) break;
    }
    for(; toEnd - 1 > toStart; --toEnd){
        if (to.charCodeAt(toEnd - 1) !== 92) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i1 = 0;
    for(; i1 <= length; ++i1){
        if (i1 === length) {
            if (toLen > length) {
                if (to.charCodeAt(toStart + i1) === 92) {
                    return toOrig.slice(toStart + i1 + 1);
                } else if (i1 === 2) {
                    return toOrig.slice(toStart + i1);
                }
            }
            if (fromLen > length) {
                if (from.charCodeAt(fromStart + i1) === 92) {
                    lastCommonSep = i1;
                } else if (i1 === 2) {
                    lastCommonSep = 3;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i1);
        const toCode = to.charCodeAt(toStart + i1);
        if (fromCode !== toCode) break;
        else if (fromCode === 92) lastCommonSep = i1;
    }
    if (i1 !== length && lastCommonSep === -1) {
        return toOrig;
    }
    let out = "";
    if (lastCommonSep === -1) lastCommonSep = 0;
    for(i1 = fromStart + lastCommonSep + 1; i1 <= fromEnd; ++i1){
        if (i1 === fromEnd || from.charCodeAt(i1) === 92) {
            if (out.length === 0) out += "..";
            else out += "\\..";
        }
    }
    if (out.length > 0) {
        return out + toOrig.slice(toStart + lastCommonSep, toEnd);
    } else {
        toStart += lastCommonSep;
        if (toOrig.charCodeAt(toStart) === 92) ++toStart;
        return toOrig.slice(toStart, toEnd);
    }
}
function toNamespacedPath(path) {
    if (typeof path !== "string") return path;
    if (path.length === 0) return "";
    const resolvedPath = resolve(path);
    if (resolvedPath.length >= 3) {
        if (resolvedPath.charCodeAt(0) === 92) {
            if (resolvedPath.charCodeAt(1) === 92) {
                const code = resolvedPath.charCodeAt(2);
                if (code !== 63 && code !== 46) {
                    return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
                }
            }
        } else if (isWindowsDeviceRoot(resolvedPath.charCodeAt(0))) {
            if (resolvedPath.charCodeAt(1) === 58 && resolvedPath.charCodeAt(2) === 92) {
                return `\\\\?\\${resolvedPath}`;
            }
        }
    }
    return path;
}
function dirname(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = -1;
    let end = -1;
    let matchedSlash = true;
    let offset = 0;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            rootEnd = offset = 1;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return path;
                        }
                        if (j !== last) {
                            rootEnd = offset = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = offset = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) rootEnd = offset = 3;
                }
            }
        }
    } else if (isPathSeparator(code)) {
        return path;
    }
    for(let i1 = len - 1; i1 >= offset; --i1){
        if (isPathSeparator(path.charCodeAt(i1))) {
            if (!matchedSlash) {
                end = i1;
                break;
            }
        } else {
            matchedSlash = false;
        }
    }
    if (end === -1) {
        if (rootEnd === -1) return ".";
        else end = rootEnd;
    }
    return path.slice(0, end);
}
function basename(path, ext = "") {
    if (ext !== undefined && typeof ext !== "string") {
        throw new TypeError('"ext" argument must be a string');
    }
    assertPath(path);
    let start = 0;
    let end = -1;
    let matchedSlash = true;
    let i1;
    if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (isWindowsDeviceRoot(drive)) {
            if (path.charCodeAt(1) === 58) start = 2;
        }
    }
    if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
        if (ext.length === path.length && ext === path) return "";
        let extIdx = ext.length - 1;
        let firstNonSlashEnd = -1;
        for(i1 = path.length - 1; i1 >= start; --i1){
            const code = path.charCodeAt(i1);
            if (isPathSeparator(code)) {
                if (!matchedSlash) {
                    start = i1 + 1;
                    break;
                }
            } else {
                if (firstNonSlashEnd === -1) {
                    matchedSlash = false;
                    firstNonSlashEnd = i1 + 1;
                }
                if (extIdx >= 0) {
                    if (code === ext.charCodeAt(extIdx)) {
                        if ((--extIdx) === -1) {
                            end = i1;
                        }
                    } else {
                        extIdx = -1;
                        end = firstNonSlashEnd;
                    }
                }
            }
        }
        if (start === end) end = firstNonSlashEnd;
        else if (end === -1) end = path.length;
        return path.slice(start, end);
    } else {
        for(i1 = path.length - 1; i1 >= start; --i1){
            if (isPathSeparator(path.charCodeAt(i1))) {
                if (!matchedSlash) {
                    start = i1 + 1;
                    break;
                }
            } else if (end === -1) {
                matchedSlash = false;
                end = i1 + 1;
            }
        }
        if (end === -1) return "";
        return path.slice(start, end);
    }
}
function extname(path) {
    assertPath(path);
    let start = 0;
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    if (path.length >= 2 && path.charCodeAt(1) === 58 && isWindowsDeviceRoot(path.charCodeAt(0))) {
        start = startPart = 2;
    }
    for(let i1 = path.length - 1; i1 >= start; --i1){
        const code = path.charCodeAt(i1);
        if (isPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i1 + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i1 + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i1;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format("\\", pathObject);
}
function parse(path) {
    assertPath(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    const len = path.length;
    if (len === 0) return ret;
    let rootEnd = 0;
    let code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            rootEnd = 1;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            rootEnd = j;
                        } else if (j !== last) {
                            rootEnd = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) {
                        if (len === 3) {
                            ret.root = ret.dir = path;
                            return ret;
                        }
                        rootEnd = 3;
                    }
                } else {
                    ret.root = ret.dir = path;
                    return ret;
                }
            }
        }
    } else if (isPathSeparator(code)) {
        ret.root = ret.dir = path;
        return ret;
    }
    if (rootEnd > 0) ret.root = path.slice(0, rootEnd);
    let startDot = -1;
    let startPart = rootEnd;
    let end = -1;
    let matchedSlash = true;
    let i1 = path.length - 1;
    let preDotState = 0;
    for(; i1 >= rootEnd; --i1){
        code = path.charCodeAt(i1);
        if (isPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i1 + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i1 + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i1;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            ret.base = ret.name = path.slice(startPart, end);
        }
    } else {
        ret.name = path.slice(startPart, startDot);
        ret.base = path.slice(startPart, end);
        ret.ext = path.slice(startDot, end);
    }
    if (startPart > 0 && startPart !== rootEnd) {
        ret.dir = path.slice(0, startPart - 1);
    } else ret.dir = ret.root;
    return ret;
}
function fromFileUrl(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    let path = decodeURIComponent(url.pathname.replace(/\//g, "\\").replace(/%(?![0-9A-Fa-f]{2})/g, "%25")).replace(/^\\*([A-Za-z]:)(\\|$)/, "$1\\");
    if (url.hostname != "") {
        path = `\\\\${url.hostname}${path}`;
    }
    return path;
}
function toFileUrl(path) {
    if (!isAbsolute(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const [, hostname, pathname] = path.match(/^(?:[/\\]{2}([^/\\]+)(?=[/\\](?:[^/\\]|$)))?(.*)/);
    const url = new URL("file:///");
    url.pathname = encodeWhitespace(pathname.replace(/%/g, "%25"));
    if (hostname != null && hostname != "localhost") {
        url.hostname = hostname;
        if (!url.hostname) {
            throw new TypeError("Invalid hostname.");
        }
    }
    return url;
}
const mod = function() {
    return {
        sep: sep,
        delimiter: delimiter,
        resolve: resolve,
        normalize: normalize,
        isAbsolute: isAbsolute,
        join: join,
        relative: relative,
        toNamespacedPath: toNamespacedPath,
        dirname: dirname,
        basename: basename,
        extname: extname,
        format: format,
        parse: parse,
        fromFileUrl: fromFileUrl,
        toFileUrl: toFileUrl
    };
}();
const sep1 = "/";
const delimiter1 = ":";
function resolve1(...pathSegments) {
    let resolvedPath = "";
    let resolvedAbsolute = false;
    for(let i1 = pathSegments.length - 1; i1 >= -1 && !resolvedAbsolute; i1--){
        let path;
        if (i1 >= 0) path = pathSegments[i1];
        else {
            const { Deno  } = globalThis;
            if (typeof Deno?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno.cwd();
        }
        assertPath(path);
        if (path.length === 0) {
            continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute = path.charCodeAt(0) === CHAR_FORWARD_SLASH;
    }
    resolvedPath = normalizeString(resolvedPath, !resolvedAbsolute, "/", isPosixPathSeparator);
    if (resolvedAbsolute) {
        if (resolvedPath.length > 0) return `/${resolvedPath}`;
        else return "/";
    } else if (resolvedPath.length > 0) return resolvedPath;
    else return ".";
}
function normalize1(path) {
    assertPath(path);
    if (path.length === 0) return ".";
    const isAbsolute1 = path.charCodeAt(0) === 47;
    const trailingSeparator = path.charCodeAt(path.length - 1) === 47;
    path = normalizeString(path, !isAbsolute1, "/", isPosixPathSeparator);
    if (path.length === 0 && !isAbsolute1) path = ".";
    if (path.length > 0 && trailingSeparator) path += "/";
    if (isAbsolute1) return `/${path}`;
    return path;
}
function isAbsolute1(path) {
    assertPath(path);
    return path.length > 0 && path.charCodeAt(0) === 47;
}
function join1(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    for(let i1 = 0, len = paths.length; i1 < len; ++i1){
        const path = paths[i1];
        assertPath(path);
        if (path.length > 0) {
            if (!joined) joined = path;
            else joined += `/${path}`;
        }
    }
    if (!joined) return ".";
    return normalize1(joined);
}
function relative1(from, to) {
    assertPath(from);
    assertPath(to);
    if (from === to) return "";
    from = resolve1(from);
    to = resolve1(to);
    if (from === to) return "";
    let fromStart = 1;
    const fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (from.charCodeAt(fromStart) !== 47) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 1;
    const toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (to.charCodeAt(toStart) !== 47) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i1 = 0;
    for(; i1 <= length; ++i1){
        if (i1 === length) {
            if (toLen > length) {
                if (to.charCodeAt(toStart + i1) === 47) {
                    return to.slice(toStart + i1 + 1);
                } else if (i1 === 0) {
                    return to.slice(toStart + i1);
                }
            } else if (fromLen > length) {
                if (from.charCodeAt(fromStart + i1) === 47) {
                    lastCommonSep = i1;
                } else if (i1 === 0) {
                    lastCommonSep = 0;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i1);
        const toCode = to.charCodeAt(toStart + i1);
        if (fromCode !== toCode) break;
        else if (fromCode === 47) lastCommonSep = i1;
    }
    let out = "";
    for(i1 = fromStart + lastCommonSep + 1; i1 <= fromEnd; ++i1){
        if (i1 === fromEnd || from.charCodeAt(i1) === 47) {
            if (out.length === 0) out += "..";
            else out += "/..";
        }
    }
    if (out.length > 0) return out + to.slice(toStart + lastCommonSep);
    else {
        toStart += lastCommonSep;
        if (to.charCodeAt(toStart) === 47) ++toStart;
        return to.slice(toStart);
    }
}
function toNamespacedPath1(path) {
    return path;
}
function dirname1(path) {
    assertPath(path);
    if (path.length === 0) return ".";
    const hasRoot = path.charCodeAt(0) === 47;
    let end = -1;
    let matchedSlash = true;
    for(let i1 = path.length - 1; i1 >= 1; --i1){
        if (path.charCodeAt(i1) === 47) {
            if (!matchedSlash) {
                end = i1;
                break;
            }
        } else {
            matchedSlash = false;
        }
    }
    if (end === -1) return hasRoot ? "/" : ".";
    if (hasRoot && end === 1) return "//";
    return path.slice(0, end);
}
function basename1(path, ext = "") {
    if (ext !== undefined && typeof ext !== "string") {
        throw new TypeError('"ext" argument must be a string');
    }
    assertPath(path);
    let start = 0;
    let end = -1;
    let matchedSlash = true;
    let i1;
    if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
        if (ext.length === path.length && ext === path) return "";
        let extIdx = ext.length - 1;
        let firstNonSlashEnd = -1;
        for(i1 = path.length - 1; i1 >= 0; --i1){
            const code = path.charCodeAt(i1);
            if (code === 47) {
                if (!matchedSlash) {
                    start = i1 + 1;
                    break;
                }
            } else {
                if (firstNonSlashEnd === -1) {
                    matchedSlash = false;
                    firstNonSlashEnd = i1 + 1;
                }
                if (extIdx >= 0) {
                    if (code === ext.charCodeAt(extIdx)) {
                        if ((--extIdx) === -1) {
                            end = i1;
                        }
                    } else {
                        extIdx = -1;
                        end = firstNonSlashEnd;
                    }
                }
            }
        }
        if (start === end) end = firstNonSlashEnd;
        else if (end === -1) end = path.length;
        return path.slice(start, end);
    } else {
        for(i1 = path.length - 1; i1 >= 0; --i1){
            if (path.charCodeAt(i1) === 47) {
                if (!matchedSlash) {
                    start = i1 + 1;
                    break;
                }
            } else if (end === -1) {
                matchedSlash = false;
                end = i1 + 1;
            }
        }
        if (end === -1) return "";
        return path.slice(start, end);
    }
}
function extname1(path) {
    assertPath(path);
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    for(let i1 = path.length - 1; i1 >= 0; --i1){
        const code = path.charCodeAt(i1);
        if (code === 47) {
            if (!matchedSlash) {
                startPart = i1 + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i1 + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i1;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format1(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format("/", pathObject);
}
function parse1(path) {
    assertPath(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    if (path.length === 0) return ret;
    const isAbsolute2 = path.charCodeAt(0) === 47;
    let start;
    if (isAbsolute2) {
        ret.root = "/";
        start = 1;
    } else {
        start = 0;
    }
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let i1 = path.length - 1;
    let preDotState = 0;
    for(; i1 >= start; --i1){
        const code = path.charCodeAt(i1);
        if (code === 47) {
            if (!matchedSlash) {
                startPart = i1 + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i1 + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i1;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            if (startPart === 0 && isAbsolute2) {
                ret.base = ret.name = path.slice(1, end);
            } else {
                ret.base = ret.name = path.slice(startPart, end);
            }
        }
    } else {
        if (startPart === 0 && isAbsolute2) {
            ret.name = path.slice(1, startDot);
            ret.base = path.slice(1, end);
        } else {
            ret.name = path.slice(startPart, startDot);
            ret.base = path.slice(startPart, end);
        }
        ret.ext = path.slice(startDot, end);
    }
    if (startPart > 0) ret.dir = path.slice(0, startPart - 1);
    else if (isAbsolute2) ret.dir = "/";
    return ret;
}
function fromFileUrl1(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    return decodeURIComponent(url.pathname.replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
}
function toFileUrl1(path) {
    if (!isAbsolute1(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const url = new URL("file:///");
    url.pathname = encodeWhitespace(path.replace(/%/g, "%25").replace(/\\/g, "%5C"));
    return url;
}
const mod1 = function() {
    return {
        sep: sep1,
        delimiter: delimiter1,
        resolve: resolve1,
        normalize: normalize1,
        isAbsolute: isAbsolute1,
        join: join1,
        relative: relative1,
        toNamespacedPath: toNamespacedPath1,
        dirname: dirname1,
        basename: basename1,
        extname: extname1,
        format: format1,
        parse: parse1,
        fromFileUrl: fromFileUrl1,
        toFileUrl: toFileUrl1
    };
}();
const path1 = isWindows ? mod : mod1;
const { basename: basename2 , delimiter: delimiter2 , dirname: dirname2 , extname: extname2 , format: format2 , fromFileUrl: fromFileUrl2 , isAbsolute: isAbsolute2 , join: join2 , normalize: normalize2 , parse: parse2 , relative: relative2 , resolve: resolve2 , sep: sep2 , toFileUrl: toFileUrl2 , toNamespacedPath: toNamespacedPath2 ,  } = path1;
function hasOwnProperty(obj, v) {
    if (obj == null) {
        return false;
    }
    return Object.prototype.hasOwnProperty.call(obj, v);
}
async function readShort(buf) {
    const high = await buf.readByte();
    if (high === null) return null;
    const low = await buf.readByte();
    if (low === null) throw new Deno.errors.UnexpectedEof();
    return high << 8 | low;
}
async function readInt(buf) {
    const high = await readShort(buf);
    if (high === null) return null;
    const low = await readShort(buf);
    if (low === null) throw new Deno.errors.UnexpectedEof();
    return high << 16 | low;
}
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
async function readLong(buf) {
    const high = await readInt(buf);
    if (high === null) return null;
    const low = await readInt(buf);
    if (low === null) throw new Deno.errors.UnexpectedEof();
    const big = BigInt(high) << 32n | BigInt(low);
    if (big > MAX_SAFE_INTEGER) {
        throw new RangeError("Long value too big to be represented as a JavaScript number.");
    }
    return Number(big);
}
function sliceLongToBytes(d, dest = new Array(8)) {
    let big = BigInt(d);
    for(let i1 = 0; i1 < 8; i1++){
        dest[7 - i1] = Number(big & 255n);
        big >>= 8n;
    }
    return dest;
}
const HEX_CHARS1 = "0123456789abcdef".split("");
const EXTRA1 = [
    -2147483648,
    8388608,
    32768,
    128
];
const SHIFT1 = [
    24,
    16,
    8,
    0
];
const blocks1 = [];
class Sha1 {
    #blocks;
    #block;
    #start;
    #bytes;
    #hBytes;
    #finalized;
    #hashed;
    #h0 = 1732584193;
    #h1 = 4023233417;
    #h2 = 2562383102;
    #h3 = 271733878;
    #h4 = 3285377520;
    #lastByteIndex = 0;
    constructor(sharedMemory3 = false){
        this.init(sharedMemory3);
    }
    init(sharedMemory) {
        if (sharedMemory) {
            blocks1[0] = blocks1[16] = blocks1[1] = blocks1[2] = blocks1[3] = blocks1[4] = blocks1[5] = blocks1[6] = blocks1[7] = blocks1[8] = blocks1[9] = blocks1[10] = blocks1[11] = blocks1[12] = blocks1[13] = blocks1[14] = blocks1[15] = 0;
            this.#blocks = blocks1;
        } else {
            this.#blocks = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ];
        }
        this.#h0 = 1732584193;
        this.#h1 = 4023233417;
        this.#h2 = 2562383102;
        this.#h3 = 271733878;
        this.#h4 = 3285377520;
        this.#block = this.#start = this.#bytes = this.#hBytes = 0;
        this.#finalized = this.#hashed = false;
    }
    update(message) {
        if (this.#finalized) {
            return this;
        }
        let msg;
        if (message instanceof ArrayBuffer) {
            msg = new Uint8Array(message);
        } else {
            msg = message;
        }
        let index = 0;
        const length = msg.length;
        const blocks2 = this.#blocks;
        while(index < length){
            let i1;
            if (this.#hashed) {
                this.#hashed = false;
                blocks2[0] = this.#block;
                blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
            }
            if (typeof msg !== "string") {
                for(i1 = this.#start; index < length && i1 < 64; ++index){
                    blocks2[i1 >> 2] |= msg[index] << SHIFT1[(i1++) & 3];
                }
            } else {
                for(i1 = this.#start; index < length && i1 < 64; ++index){
                    let code = msg.charCodeAt(index);
                    if (code < 128) {
                        blocks2[i1 >> 2] |= code << SHIFT1[(i1++) & 3];
                    } else if (code < 2048) {
                        blocks2[i1 >> 2] |= (192 | code >> 6) << SHIFT1[(i1++) & 3];
                        blocks2[i1 >> 2] |= (128 | code & 63) << SHIFT1[(i1++) & 3];
                    } else if (code < 55296 || code >= 57344) {
                        blocks2[i1 >> 2] |= (224 | code >> 12) << SHIFT1[(i1++) & 3];
                        blocks2[i1 >> 2] |= (128 | code >> 6 & 63) << SHIFT1[(i1++) & 3];
                        blocks2[i1 >> 2] |= (128 | code & 63) << SHIFT1[(i1++) & 3];
                    } else {
                        code = 65536 + ((code & 1023) << 10 | msg.charCodeAt(++index) & 1023);
                        blocks2[i1 >> 2] |= (240 | code >> 18) << SHIFT1[(i1++) & 3];
                        blocks2[i1 >> 2] |= (128 | code >> 12 & 63) << SHIFT1[(i1++) & 3];
                        blocks2[i1 >> 2] |= (128 | code >> 6 & 63) << SHIFT1[(i1++) & 3];
                        blocks2[i1 >> 2] |= (128 | code & 63) << SHIFT1[(i1++) & 3];
                    }
                }
            }
            this.#lastByteIndex = i1;
            this.#bytes += i1 - this.#start;
            if (i1 >= 64) {
                this.#block = blocks2[16];
                this.#start = i1 - 64;
                this.hash();
                this.#hashed = true;
            } else {
                this.#start = i1;
            }
        }
        if (this.#bytes > 4294967295) {
            this.#hBytes += this.#bytes / 4294967296 >>> 0;
            this.#bytes = this.#bytes >>> 0;
        }
        return this;
    }
    finalize() {
        if (this.#finalized) {
            return;
        }
        this.#finalized = true;
        const blocks2 = this.#blocks;
        const i1 = this.#lastByteIndex;
        blocks2[16] = this.#block;
        blocks2[i1 >> 2] |= EXTRA1[i1 & 3];
        this.#block = blocks2[16];
        if (i1 >= 56) {
            if (!this.#hashed) {
                this.hash();
            }
            blocks2[0] = this.#block;
            blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
        }
        blocks2[14] = this.#hBytes << 3 | this.#bytes >>> 29;
        blocks2[15] = this.#bytes << 3;
        this.hash();
    }
    hash() {
        let a = this.#h0;
        let b = this.#h1;
        let c = this.#h2;
        let d = this.#h3;
        let e = this.#h4;
        let f;
        let j;
        let t;
        const blocks2 = this.#blocks;
        for(j = 16; j < 80; ++j){
            t = blocks2[j - 3] ^ blocks2[j - 8] ^ blocks2[j - 14] ^ blocks2[j - 16];
            blocks2[j] = t << 1 | t >>> 31;
        }
        for(j = 0; j < 20; j += 5){
            f = b & c | ~b & d;
            t = a << 5 | a >>> 27;
            e = t + f + e + 1518500249 + blocks2[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a & b | ~a & c;
            t = e << 5 | e >>> 27;
            d = t + f + d + 1518500249 + blocks2[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e & a | ~e & b;
            t = d << 5 | d >>> 27;
            c = t + f + c + 1518500249 + blocks2[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d & e | ~d & a;
            t = c << 5 | c >>> 27;
            b = t + f + b + 1518500249 + blocks2[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c & d | ~c & e;
            t = b << 5 | b >>> 27;
            a = t + f + a + 1518500249 + blocks2[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 40; j += 5){
            f = b ^ c ^ d;
            t = a << 5 | a >>> 27;
            e = t + f + e + 1859775393 + blocks2[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a ^ b ^ c;
            t = e << 5 | e >>> 27;
            d = t + f + d + 1859775393 + blocks2[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e ^ a ^ b;
            t = d << 5 | d >>> 27;
            c = t + f + c + 1859775393 + blocks2[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d ^ e ^ a;
            t = c << 5 | c >>> 27;
            b = t + f + b + 1859775393 + blocks2[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c ^ d ^ e;
            t = b << 5 | b >>> 27;
            a = t + f + a + 1859775393 + blocks2[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 60; j += 5){
            f = b & c | b & d | c & d;
            t = a << 5 | a >>> 27;
            e = t + f + e - 1894007588 + blocks2[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a & b | a & c | b & c;
            t = e << 5 | e >>> 27;
            d = t + f + d - 1894007588 + blocks2[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e & a | e & b | a & b;
            t = d << 5 | d >>> 27;
            c = t + f + c - 1894007588 + blocks2[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d & e | d & a | e & a;
            t = c << 5 | c >>> 27;
            b = t + f + b - 1894007588 + blocks2[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c & d | c & e | d & e;
            t = b << 5 | b >>> 27;
            a = t + f + a - 1894007588 + blocks2[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 80; j += 5){
            f = b ^ c ^ d;
            t = a << 5 | a >>> 27;
            e = t + f + e - 899497514 + blocks2[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a ^ b ^ c;
            t = e << 5 | e >>> 27;
            d = t + f + d - 899497514 + blocks2[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e ^ a ^ b;
            t = d << 5 | d >>> 27;
            c = t + f + c - 899497514 + blocks2[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d ^ e ^ a;
            t = c << 5 | c >>> 27;
            b = t + f + b - 899497514 + blocks2[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c ^ d ^ e;
            t = b << 5 | b >>> 27;
            a = t + f + a - 899497514 + blocks2[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        this.#h0 = this.#h0 + a >>> 0;
        this.#h1 = this.#h1 + b >>> 0;
        this.#h2 = this.#h2 + c >>> 0;
        this.#h3 = this.#h3 + d >>> 0;
        this.#h4 = this.#h4 + e >>> 0;
    }
    hex() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        return HEX_CHARS1[h0 >> 28 & 15] + HEX_CHARS1[h0 >> 24 & 15] + HEX_CHARS1[h0 >> 20 & 15] + HEX_CHARS1[h0 >> 16 & 15] + HEX_CHARS1[h0 >> 12 & 15] + HEX_CHARS1[h0 >> 8 & 15] + HEX_CHARS1[h0 >> 4 & 15] + HEX_CHARS1[h0 & 15] + HEX_CHARS1[h1 >> 28 & 15] + HEX_CHARS1[h1 >> 24 & 15] + HEX_CHARS1[h1 >> 20 & 15] + HEX_CHARS1[h1 >> 16 & 15] + HEX_CHARS1[h1 >> 12 & 15] + HEX_CHARS1[h1 >> 8 & 15] + HEX_CHARS1[h1 >> 4 & 15] + HEX_CHARS1[h1 & 15] + HEX_CHARS1[h2 >> 28 & 15] + HEX_CHARS1[h2 >> 24 & 15] + HEX_CHARS1[h2 >> 20 & 15] + HEX_CHARS1[h2 >> 16 & 15] + HEX_CHARS1[h2 >> 12 & 15] + HEX_CHARS1[h2 >> 8 & 15] + HEX_CHARS1[h2 >> 4 & 15] + HEX_CHARS1[h2 & 15] + HEX_CHARS1[h3 >> 28 & 15] + HEX_CHARS1[h3 >> 24 & 15] + HEX_CHARS1[h3 >> 20 & 15] + HEX_CHARS1[h3 >> 16 & 15] + HEX_CHARS1[h3 >> 12 & 15] + HEX_CHARS1[h3 >> 8 & 15] + HEX_CHARS1[h3 >> 4 & 15] + HEX_CHARS1[h3 & 15] + HEX_CHARS1[h4 >> 28 & 15] + HEX_CHARS1[h4 >> 24 & 15] + HEX_CHARS1[h4 >> 20 & 15] + HEX_CHARS1[h4 >> 16 & 15] + HEX_CHARS1[h4 >> 12 & 15] + HEX_CHARS1[h4 >> 8 & 15] + HEX_CHARS1[h4 >> 4 & 15] + HEX_CHARS1[h4 & 15];
    }
    toString() {
        return this.hex();
    }
    digest() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        return [
            h0 >> 24 & 255,
            h0 >> 16 & 255,
            h0 >> 8 & 255,
            h0 & 255,
            h1 >> 24 & 255,
            h1 >> 16 & 255,
            h1 >> 8 & 255,
            h1 & 255,
            h2 >> 24 & 255,
            h2 >> 16 & 255,
            h2 >> 8 & 255,
            h2 & 255,
            h3 >> 24 & 255,
            h3 >> 16 & 255,
            h3 >> 8 & 255,
            h3 & 255,
            h4 >> 24 & 255,
            h4 >> 16 & 255,
            h4 >> 8 & 255,
            h4 & 255, 
        ];
    }
    array() {
        return this.digest();
    }
    arrayBuffer() {
        this.finalize();
        const buffer = new ArrayBuffer(20);
        const dataView = new DataView(buffer);
        dataView.setUint32(0, this.#h0);
        dataView.setUint32(4, this.#h1);
        dataView.setUint32(8, this.#h2);
        dataView.setUint32(12, this.#h3);
        dataView.setUint32(16, this.#h4);
        return buffer;
    }
}
class HmacSha1 extends Sha1 {
    #sharedMemory;
    #inner;
    #oKeyPad;
    constructor(secretKey1, sharedMemory4 = false){
        super(sharedMemory4);
        let key1;
        if (typeof secretKey1 === "string") {
            const bytes = [];
            const length = secretKey1.length;
            let index = 0;
            for(let i1 = 0; i1 < length; i1++){
                let code = secretKey1.charCodeAt(i1);
                if (code < 128) {
                    bytes[index++] = code;
                } else if (code < 2048) {
                    bytes[index++] = 192 | code >> 6;
                    bytes[index++] = 128 | code & 63;
                } else if (code < 55296 || code >= 57344) {
                    bytes[index++] = 224 | code >> 12;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                } else {
                    code = 65536 + ((code & 1023) << 10 | secretKey1.charCodeAt(++i1) & 1023);
                    bytes[index++] = 240 | code >> 18;
                    bytes[index++] = 128 | code >> 12 & 63;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                }
            }
            key1 = bytes;
        } else {
            if (secretKey1 instanceof ArrayBuffer) {
                key1 = new Uint8Array(secretKey1);
            } else {
                key1 = secretKey1;
            }
        }
        if (key1.length > 64) {
            key1 = new Sha1(true).update(key1).array();
        }
        const oKeyPad1 = [];
        const iKeyPad1 = [];
        for(let i1 = 0; i1 < 64; i1++){
            const b = key1[i1] || 0;
            oKeyPad1[i1] = 92 ^ b;
            iKeyPad1[i1] = 54 ^ b;
        }
        this.update(iKeyPad1);
        this.#oKeyPad = oKeyPad1;
        this.#inner = true;
        this.#sharedMemory = sharedMemory4;
    }
    finalize() {
        super.finalize();
        if (this.#inner) {
            this.#inner = false;
            const innerHash = this.array();
            super.init(this.#sharedMemory);
            this.update(this.#oKeyPad);
            this.update(innerHash);
            super.finalize();
        }
    }
}
var OpCode;
(function(OpCode1) {
    OpCode1[OpCode1["Continue"] = 0] = "Continue";
    OpCode1[OpCode1["TextFrame"] = 1] = "TextFrame";
    OpCode1[OpCode1["BinaryFrame"] = 2] = "BinaryFrame";
    OpCode1[OpCode1["Close"] = 8] = "Close";
    OpCode1[OpCode1["Ping"] = 9] = "Ping";
    OpCode1[OpCode1["Pong"] = 10] = "Pong";
})(OpCode || (OpCode = {
}));
function isWebSocketCloseEvent(a) {
    return hasOwnProperty(a, "code");
}
function isWebSocketPingEvent(a) {
    return Array.isArray(a) && a[0] === "ping" && a[1] instanceof Uint8Array;
}
function isWebSocketPongEvent(a) {
    return Array.isArray(a) && a[0] === "pong" && a[1] instanceof Uint8Array;
}
function unmask(payload, mask) {
    if (mask) {
        for(let i2 = 0, len = payload.length; i2 < len; i2++){
            payload[i2] ^= mask[i2 & 3];
        }
    }
}
async function writeFrame(frame, writer3) {
    const payloadLength = frame.payload.byteLength;
    let header;
    const hasMask = frame.mask ? 128 : 0;
    if (frame.mask && frame.mask.byteLength !== 4) {
        throw new Error("invalid mask. mask must be 4 bytes: length=" + frame.mask.byteLength);
    }
    if (payloadLength < 126) {
        header = new Uint8Array([
            128 | frame.opcode,
            hasMask | payloadLength
        ]);
    } else if (payloadLength < 65535) {
        header = new Uint8Array([
            128 | frame.opcode,
            hasMask | 126,
            payloadLength >>> 8,
            payloadLength & 255, 
        ]);
    } else {
        header = new Uint8Array([
            128 | frame.opcode,
            hasMask | 127,
            ...sliceLongToBytes(payloadLength), 
        ]);
    }
    if (frame.mask) {
        header = concat(header, frame.mask);
    }
    unmask(frame.payload, frame.mask);
    header = concat(header, frame.payload);
    const w = BufWriter.create(writer3);
    await w.write(header);
    await w.flush();
}
async function readFrame(buf) {
    let b = await buf.readByte();
    assert(b !== null);
    let isLastFrame = false;
    switch(b >>> 4){
        case 8:
            isLastFrame = true;
            break;
        case 0:
            isLastFrame = false;
            break;
        default:
            throw new Error("invalid signature");
    }
    const opcode = b & 15;
    b = await buf.readByte();
    assert(b !== null);
    const hasMask = b >>> 7;
    let payloadLength = b & 127;
    if (payloadLength === 126) {
        const l = await readShort(buf);
        assert(l !== null);
        payloadLength = l;
    } else if (payloadLength === 127) {
        const l = await readLong(buf);
        assert(l !== null);
        payloadLength = Number(l);
    }
    let mask;
    if (hasMask) {
        mask = new Uint8Array(4);
        assert(await buf.readFull(mask) !== null);
    }
    const payload = new Uint8Array(payloadLength);
    assert(await buf.readFull(payload) !== null);
    return {
        isLastFrame,
        opcode,
        mask,
        payload
    };
}
class WebSocketImpl {
    conn;
    mask;
    bufReader;
    bufWriter;
    sendQueue = [];
    constructor({ conn , bufReader , bufWriter , mask  }){
        this.conn = conn;
        this.mask = mask;
        this.bufReader = bufReader || new BufReader(conn);
        this.bufWriter = bufWriter || new BufWriter(conn);
    }
    async *[Symbol.asyncIterator]() {
        const decoder1 = new TextDecoder();
        let frames = [];
        let payloadsLength = 0;
        while(!this._isClosed){
            let frame;
            try {
                frame = await readFrame(this.bufReader);
            } catch  {
                this.ensureSocketClosed();
                break;
            }
            unmask(frame.payload, frame.mask);
            switch(frame.opcode){
                case OpCode.TextFrame:
                case OpCode.BinaryFrame:
                case OpCode.Continue:
                    frames.push(frame);
                    payloadsLength += frame.payload.length;
                    if (frame.isLastFrame) {
                        const concat1 = new Uint8Array(payloadsLength);
                        let offs = 0;
                        for (const frame1 of frames){
                            concat1.set(frame1.payload, offs);
                            offs += frame1.payload.length;
                        }
                        if (frames[0].opcode === OpCode.TextFrame) {
                            yield decoder1.decode(concat1);
                        } else {
                            yield concat1;
                        }
                        frames = [];
                        payloadsLength = 0;
                    }
                    break;
                case OpCode.Close:
                    {
                        const code = frame.payload[0] << 8 | frame.payload[1];
                        const reason = decoder1.decode(frame.payload.subarray(2, frame.payload.length));
                        await this.close(code, reason);
                        yield {
                            code,
                            reason
                        };
                        return;
                    }
                case OpCode.Ping:
                    await this.enqueue({
                        opcode: OpCode.Pong,
                        payload: frame.payload,
                        isLastFrame: true
                    });
                    yield [
                        "ping",
                        frame.payload
                    ];
                    break;
                case OpCode.Pong:
                    yield [
                        "pong",
                        frame.payload
                    ];
                    break;
                default:
            }
        }
    }
    dequeue() {
        const [entry] = this.sendQueue;
        if (!entry) return;
        if (this._isClosed) return;
        const { d , frame  } = entry;
        writeFrame(frame, this.bufWriter).then(()=>d.resolve()
        ).catch((e)=>d.reject(e)
        ).finally(()=>{
            this.sendQueue.shift();
            this.dequeue();
        });
    }
    enqueue(frame) {
        if (this._isClosed) {
            throw new Deno.errors.ConnectionReset("Socket has already been closed");
        }
        const d = deferred();
        this.sendQueue.push({
            d,
            frame
        });
        if (this.sendQueue.length === 1) {
            this.dequeue();
        }
        return d;
    }
    send(data) {
        const opcode = typeof data === "string" ? OpCode.TextFrame : OpCode.BinaryFrame;
        const payload = typeof data === "string" ? new TextEncoder().encode(data) : data;
        const isLastFrame = true;
        const frame = {
            isLastFrame: true,
            opcode,
            payload,
            mask: this.mask
        };
        return this.enqueue(frame);
    }
    ping(data = "") {
        const payload = typeof data === "string" ? new TextEncoder().encode(data) : data;
        const frame = {
            isLastFrame: true,
            opcode: OpCode.Ping,
            mask: this.mask,
            payload
        };
        return this.enqueue(frame);
    }
    _isClosed = false;
    get isClosed() {
        return this._isClosed;
    }
    async close(code = 1000, reason) {
        try {
            const header = [
                code >>> 8,
                code & 255
            ];
            let payload;
            if (reason) {
                const reasonBytes = new TextEncoder().encode(reason);
                payload = new Uint8Array(2 + reasonBytes.byteLength);
                payload.set(header);
                payload.set(reasonBytes, 2);
            } else {
                payload = new Uint8Array(header);
            }
            await this.enqueue({
                isLastFrame: true,
                opcode: OpCode.Close,
                mask: this.mask,
                payload
            });
        } catch (e) {
            throw e;
        } finally{
            this.ensureSocketClosed();
        }
    }
    closeForce() {
        this.ensureSocketClosed();
    }
    ensureSocketClosed() {
        if (this.isClosed) return;
        try {
            this.conn.close();
        } catch (e) {
            console.error(e);
        } finally{
            this._isClosed = true;
            const rest = this.sendQueue;
            this.sendQueue = [];
            rest.forEach((e)=>e.d.reject(new Deno.errors.ConnectionReset("Socket has already been closed"))
            );
        }
    }
}
function acceptable(req) {
    const upgrade = req.headers.get("upgrade");
    if (!upgrade || upgrade.toLowerCase() !== "websocket") {
        return false;
    }
    const secKey = req.headers.get("sec-websocket-key");
    return req.headers.has("sec-websocket-key") && typeof secKey === "string" && secKey.length > 0;
}
const kGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
function createSecAccept(nonce) {
    const sha1 = new Sha1();
    sha1.update(nonce + kGUID);
    const bytes = sha1.digest();
    return btoa(String.fromCharCode(...bytes));
}
async function acceptWebSocket(req) {
    const { conn: conn1 , headers , bufReader: bufReader1 , bufWriter: bufWriter1  } = req;
    if (acceptable(req)) {
        const sock = new WebSocketImpl({
            conn: conn1,
            bufReader: bufReader1,
            bufWriter: bufWriter1
        });
        const secKey = headers.get("sec-websocket-key");
        if (typeof secKey !== "string") {
            throw new Error("sec-websocket-key is not provided");
        }
        const secAccept = createSecAccept(secKey);
        const newHeaders = new Headers({
            Upgrade: "websocket",
            Connection: "Upgrade",
            "Sec-WebSocket-Accept": secAccept
        });
        const secProtocol = headers.get("sec-websocket-protocol");
        if (typeof secProtocol === "string") {
            newHeaders.set("Sec-WebSocket-Protocol", secProtocol);
        }
        const secVersion = headers.get("sec-websocket-version");
        if (typeof secVersion === "string") {
            newHeaders.set("Sec-WebSocket-Version", secVersion);
        }
        await writeResponse(bufWriter1, {
            status: 101,
            headers: newHeaders
        });
        return sock;
    }
    throw new Error("request is not acceptable");
}
const db = JSON.parse(`{\n  "application/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "application/3gpdash-qoe-report+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/3gpp-ims+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/3gpphal+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/3gpphalforms+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/a2l": {\n    "source": "iana"\n  },\n  "application/activemessage": {\n    "source": "iana"\n  },\n  "application/activity+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-costmap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-costmapfilter+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-directory+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointcost+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointcostparams+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointprop+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointpropparams+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-error+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-networkmap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-networkmapfilter+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-updatestreamcontrol+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-updatestreamparams+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/aml": {\n    "source": "iana"\n  },\n  "application/andrew-inset": {\n    "source": "iana",\n    "extensions": ["ez"]\n  },\n  "application/applefile": {\n    "source": "iana"\n  },\n  "application/applixware": {\n    "source": "apache",\n    "extensions": ["aw"]\n  },\n  "application/atf": {\n    "source": "iana"\n  },\n  "application/atfx": {\n    "source": "iana"\n  },\n  "application/atom+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atom"]\n  },\n  "application/atomcat+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atomcat"]\n  },\n  "application/atomdeleted+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atomdeleted"]\n  },\n  "application/atomicmail": {\n    "source": "iana"\n  },\n  "application/atomsvc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atomsvc"]\n  },\n  "application/atsc-dwd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dwd"]\n  },\n  "application/atsc-dynamic-event-message": {\n    "source": "iana"\n  },\n  "application/atsc-held+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["held"]\n  },\n  "application/atsc-rdt+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/atsc-rsat+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rsat"]\n  },\n  "application/atxml": {\n    "source": "iana"\n  },\n  "application/auth-policy+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/bacnet-xdd+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/batch-smtp": {\n    "source": "iana"\n  },\n  "application/bdoc": {\n    "compressible": false,\n    "extensions": ["bdoc"]\n  },\n  "application/beep+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/calendar+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/calendar+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xcs"]\n  },\n  "application/call-completion": {\n    "source": "iana"\n  },\n  "application/cals-1840": {\n    "source": "iana"\n  },\n  "application/captive+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cbor": {\n    "source": "iana"\n  },\n  "application/cbor-seq": {\n    "source": "iana"\n  },\n  "application/cccex": {\n    "source": "iana"\n  },\n  "application/ccmp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ccxml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ccxml"]\n  },\n  "application/cdfx+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["cdfx"]\n  },\n  "application/cdmi-capability": {\n    "source": "iana",\n    "extensions": ["cdmia"]\n  },\n  "application/cdmi-container": {\n    "source": "iana",\n    "extensions": ["cdmic"]\n  },\n  "application/cdmi-domain": {\n    "source": "iana",\n    "extensions": ["cdmid"]\n  },\n  "application/cdmi-object": {\n    "source": "iana",\n    "extensions": ["cdmio"]\n  },\n  "application/cdmi-queue": {\n    "source": "iana",\n    "extensions": ["cdmiq"]\n  },\n  "application/cdni": {\n    "source": "iana"\n  },\n  "application/cea": {\n    "source": "iana"\n  },\n  "application/cea-2018+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cellml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cfw": {\n    "source": "iana"\n  },\n  "application/clr": {\n    "source": "iana"\n  },\n  "application/clue+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/clue_info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cms": {\n    "source": "iana"\n  },\n  "application/cnrp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/coap-group+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/coap-payload": {\n    "source": "iana"\n  },\n  "application/commonground": {\n    "source": "iana"\n  },\n  "application/conference-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cose": {\n    "source": "iana"\n  },\n  "application/cose-key": {\n    "source": "iana"\n  },\n  "application/cose-key-set": {\n    "source": "iana"\n  },\n  "application/cpl+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/csrattrs": {\n    "source": "iana"\n  },\n  "application/csta+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cstadata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/csvm+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cu-seeme": {\n    "source": "apache",\n    "extensions": ["cu"]\n  },\n  "application/cwt": {\n    "source": "iana"\n  },\n  "application/cybercash": {\n    "source": "iana"\n  },\n  "application/dart": {\n    "compressible": true\n  },\n  "application/dash+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mpd"]\n  },\n  "application/dashdelta": {\n    "source": "iana"\n  },\n  "application/davmount+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["davmount"]\n  },\n  "application/dca-rft": {\n    "source": "iana"\n  },\n  "application/dcd": {\n    "source": "iana"\n  },\n  "application/dec-dx": {\n    "source": "iana"\n  },\n  "application/dialog-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dicom": {\n    "source": "iana"\n  },\n  "application/dicom+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dicom+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dii": {\n    "source": "iana"\n  },\n  "application/dit": {\n    "source": "iana"\n  },\n  "application/dns": {\n    "source": "iana"\n  },\n  "application/dns+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dns-message": {\n    "source": "iana"\n  },\n  "application/docbook+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["dbk"]\n  },\n  "application/dots+cbor": {\n    "source": "iana"\n  },\n  "application/dskpp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dssc+der": {\n    "source": "iana",\n    "extensions": ["dssc"]\n  },\n  "application/dssc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdssc"]\n  },\n  "application/dvcs": {\n    "source": "iana"\n  },\n  "application/ecmascript": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["es","ecma"]\n  },\n  "application/edi-consent": {\n    "source": "iana"\n  },\n  "application/edi-x12": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/edifact": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/efi": {\n    "source": "iana"\n  },\n  "application/elm+json": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/elm+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.cap+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/emergencycalldata.comment+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.control+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.deviceinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.ecall.msd": {\n    "source": "iana"\n  },\n  "application/emergencycalldata.providerinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.serviceinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.subscriberinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.veds+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emma+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["emma"]\n  },\n  "application/emotionml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["emotionml"]\n  },\n  "application/encaprtp": {\n    "source": "iana"\n  },\n  "application/epp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/epub+zip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["epub"]\n  },\n  "application/eshop": {\n    "source": "iana"\n  },\n  "application/exi": {\n    "source": "iana",\n    "extensions": ["exi"]\n  },\n  "application/expect-ct-report+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/fastinfoset": {\n    "source": "iana"\n  },\n  "application/fastsoap": {\n    "source": "iana"\n  },\n  "application/fdt+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["fdt"]\n  },\n  "application/fhir+json": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/fhir+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/fido.trusted-apps+json": {\n    "compressible": true\n  },\n  "application/fits": {\n    "source": "iana"\n  },\n  "application/flexfec": {\n    "source": "iana"\n  },\n  "application/font-sfnt": {\n    "source": "iana"\n  },\n  "application/font-tdpfr": {\n    "source": "iana",\n    "extensions": ["pfr"]\n  },\n  "application/font-woff": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/framework-attributes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/geo+json": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["geojson"]\n  },\n  "application/geo+json-seq": {\n    "source": "iana"\n  },\n  "application/geopackage+sqlite3": {\n    "source": "iana"\n  },\n  "application/geoxacml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/gltf-buffer": {\n    "source": "iana"\n  },\n  "application/gml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["gml"]\n  },\n  "application/gpx+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["gpx"]\n  },\n  "application/gxf": {\n    "source": "apache",\n    "extensions": ["gxf"]\n  },\n  "application/gzip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["gz"]\n  },\n  "application/h224": {\n    "source": "iana"\n  },\n  "application/held+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/hjson": {\n    "extensions": ["hjson"]\n  },\n  "application/http": {\n    "source": "iana"\n  },\n  "application/hyperstudio": {\n    "source": "iana",\n    "extensions": ["stk"]\n  },\n  "application/ibe-key-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ibe-pkg-reply+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ibe-pp-data": {\n    "source": "iana"\n  },\n  "application/iges": {\n    "source": "iana"\n  },\n  "application/im-iscomposing+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/index": {\n    "source": "iana"\n  },\n  "application/index.cmd": {\n    "source": "iana"\n  },\n  "application/index.obj": {\n    "source": "iana"\n  },\n  "application/index.response": {\n    "source": "iana"\n  },\n  "application/index.vnd": {\n    "source": "iana"\n  },\n  "application/inkml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ink","inkml"]\n  },\n  "application/iotp": {\n    "source": "iana"\n  },\n  "application/ipfix": {\n    "source": "iana",\n    "extensions": ["ipfix"]\n  },\n  "application/ipp": {\n    "source": "iana"\n  },\n  "application/isup": {\n    "source": "iana"\n  },\n  "application/its+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["its"]\n  },\n  "application/java-archive": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["jar","war","ear"]\n  },\n  "application/java-serialized-object": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["ser"]\n  },\n  "application/java-vm": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["class"]\n  },\n  "application/javascript": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["js","mjs"]\n  },\n  "application/jf2feed+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jose": {\n    "source": "iana"\n  },\n  "application/jose+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jrd+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jscalendar+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/json": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["json","map"]\n  },\n  "application/json-patch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/json-seq": {\n    "source": "iana"\n  },\n  "application/json5": {\n    "extensions": ["json5"]\n  },\n  "application/jsonml+json": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["jsonml"]\n  },\n  "application/jwk+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jwk-set+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jwt": {\n    "source": "iana"\n  },\n  "application/kpml-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/kpml-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ld+json": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["jsonld"]\n  },\n  "application/lgr+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lgr"]\n  },\n  "application/link-format": {\n    "source": "iana"\n  },\n  "application/load-control+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/lost+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lostxml"]\n  },\n  "application/lostsync+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/lpf+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/lxf": {\n    "source": "iana"\n  },\n  "application/mac-binhex40": {\n    "source": "iana",\n    "extensions": ["hqx"]\n  },\n  "application/mac-compactpro": {\n    "source": "apache",\n    "extensions": ["cpt"]\n  },\n  "application/macwriteii": {\n    "source": "iana"\n  },\n  "application/mads+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mads"]\n  },\n  "application/manifest+json": {\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["webmanifest"]\n  },\n  "application/marc": {\n    "source": "iana",\n    "extensions": ["mrc"]\n  },\n  "application/marcxml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mrcx"]\n  },\n  "application/mathematica": {\n    "source": "iana",\n    "extensions": ["ma","nb","mb"]\n  },\n  "application/mathml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mathml"]\n  },\n  "application/mathml-content+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mathml-presentation+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-associated-procedure-description+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-deregister+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-envelope+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-msk+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-msk-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-protection-description+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-reception-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-register+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-register-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-schedule+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-user-service-description+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbox": {\n    "source": "iana",\n    "extensions": ["mbox"]\n  },\n  "application/media-policy-dataset+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/media_control+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mediaservercontrol+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mscml"]\n  },\n  "application/merge-patch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/metalink+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["metalink"]\n  },\n  "application/metalink4+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["meta4"]\n  },\n  "application/mets+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mets"]\n  },\n  "application/mf4": {\n    "source": "iana"\n  },\n  "application/mikey": {\n    "source": "iana"\n  },\n  "application/mipc": {\n    "source": "iana"\n  },\n  "application/mmt-aei+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["maei"]\n  },\n  "application/mmt-usd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["musd"]\n  },\n  "application/mods+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mods"]\n  },\n  "application/moss-keys": {\n    "source": "iana"\n  },\n  "application/moss-signature": {\n    "source": "iana"\n  },\n  "application/mosskey-data": {\n    "source": "iana"\n  },\n  "application/mosskey-request": {\n    "source": "iana"\n  },\n  "application/mp21": {\n    "source": "iana",\n    "extensions": ["m21","mp21"]\n  },\n  "application/mp4": {\n    "source": "iana",\n    "extensions": ["mp4s","m4p"]\n  },\n  "application/mpeg4-generic": {\n    "source": "iana"\n  },\n  "application/mpeg4-iod": {\n    "source": "iana"\n  },\n  "application/mpeg4-iod-xmt": {\n    "source": "iana"\n  },\n  "application/mrb-consumer+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mrb-publish+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/msc-ivr+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/msc-mixer+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/msword": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["doc","dot"]\n  },\n  "application/mud+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/multipart-core": {\n    "source": "iana"\n  },\n  "application/mxf": {\n    "source": "iana",\n    "extensions": ["mxf"]\n  },\n  "application/n-quads": {\n    "source": "iana",\n    "extensions": ["nq"]\n  },\n  "application/n-triples": {\n    "source": "iana",\n    "extensions": ["nt"]\n  },\n  "application/nasdata": {\n    "source": "iana"\n  },\n  "application/news-checkgroups": {\n    "source": "iana",\n    "charset": "US-ASCII"\n  },\n  "application/news-groupinfo": {\n    "source": "iana",\n    "charset": "US-ASCII"\n  },\n  "application/news-transmission": {\n    "source": "iana"\n  },\n  "application/nlsml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/node": {\n    "source": "iana",\n    "extensions": ["cjs"]\n  },\n  "application/nss": {\n    "source": "iana"\n  },\n  "application/oauth-authz-req+jwt": {\n    "source": "iana"\n  },\n  "application/ocsp-request": {\n    "source": "iana"\n  },\n  "application/ocsp-response": {\n    "source": "iana"\n  },\n  "application/octet-stream": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["bin","dms","lrf","mar","so","dist","distz","pkg","bpk","dump","elc","deploy","exe","dll","deb","dmg","iso","img","msi","msp","msm","buffer"]\n  },\n  "application/oda": {\n    "source": "iana",\n    "extensions": ["oda"]\n  },\n  "application/odm+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/odx": {\n    "source": "iana"\n  },\n  "application/oebps-package+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["opf"]\n  },\n  "application/ogg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ogx"]\n  },\n  "application/omdoc+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["omdoc"]\n  },\n  "application/onenote": {\n    "source": "apache",\n    "extensions": ["onetoc","onetoc2","onetmp","onepkg"]\n  },\n  "application/opc-nodeset+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/oscore": {\n    "source": "iana"\n  },\n  "application/oxps": {\n    "source": "iana",\n    "extensions": ["oxps"]\n  },\n  "application/p2p-overlay+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["relo"]\n  },\n  "application/parityfec": {\n    "source": "iana"\n  },\n  "application/passport": {\n    "source": "iana"\n  },\n  "application/patch-ops-error+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xer"]\n  },\n  "application/pdf": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["pdf"]\n  },\n  "application/pdx": {\n    "source": "iana"\n  },\n  "application/pem-certificate-chain": {\n    "source": "iana"\n  },\n  "application/pgp-encrypted": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["pgp"]\n  },\n  "application/pgp-keys": {\n    "source": "iana"\n  },\n  "application/pgp-signature": {\n    "source": "iana",\n    "extensions": ["asc","sig"]\n  },\n  "application/pics-rules": {\n    "source": "apache",\n    "extensions": ["prf"]\n  },\n  "application/pidf+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/pidf-diff+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/pkcs10": {\n    "source": "iana",\n    "extensions": ["p10"]\n  },\n  "application/pkcs12": {\n    "source": "iana"\n  },\n  "application/pkcs7-mime": {\n    "source": "iana",\n    "extensions": ["p7m","p7c"]\n  },\n  "application/pkcs7-signature": {\n    "source": "iana",\n    "extensions": ["p7s"]\n  },\n  "application/pkcs8": {\n    "source": "iana",\n    "extensions": ["p8"]\n  },\n  "application/pkcs8-encrypted": {\n    "source": "iana"\n  },\n  "application/pkix-attr-cert": {\n    "source": "iana",\n    "extensions": ["ac"]\n  },\n  "application/pkix-cert": {\n    "source": "iana",\n    "extensions": ["cer"]\n  },\n  "application/pkix-crl": {\n    "source": "iana",\n    "extensions": ["crl"]\n  },\n  "application/pkix-pkipath": {\n    "source": "iana",\n    "extensions": ["pkipath"]\n  },\n  "application/pkixcmp": {\n    "source": "iana",\n    "extensions": ["pki"]\n  },\n  "application/pls+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["pls"]\n  },\n  "application/poc-settings+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/postscript": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ai","eps","ps"]\n  },\n  "application/ppsp-tracker+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/problem+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/problem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/provenance+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["provx"]\n  },\n  "application/prs.alvestrand.titrax-sheet": {\n    "source": "iana"\n  },\n  "application/prs.cww": {\n    "source": "iana",\n    "extensions": ["cww"]\n  },\n  "application/prs.cyn": {\n    "source": "iana",\n    "charset": "7-BIT"\n  },\n  "application/prs.hpub+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/prs.nprend": {\n    "source": "iana"\n  },\n  "application/prs.plucker": {\n    "source": "iana"\n  },\n  "application/prs.rdf-xml-crypt": {\n    "source": "iana"\n  },\n  "application/prs.xsf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/pskc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["pskcxml"]\n  },\n  "application/pvd+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/qsig": {\n    "source": "iana"\n  },\n  "application/raml+yaml": {\n    "compressible": true,\n    "extensions": ["raml"]\n  },\n  "application/raptorfec": {\n    "source": "iana"\n  },\n  "application/rdap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/rdf+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rdf","owl"]\n  },\n  "application/reginfo+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rif"]\n  },\n  "application/relax-ng-compact-syntax": {\n    "source": "iana",\n    "extensions": ["rnc"]\n  },\n  "application/remote-printing": {\n    "source": "iana"\n  },\n  "application/reputon+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/resource-lists+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rl"]\n  },\n  "application/resource-lists-diff+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rld"]\n  },\n  "application/rfc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/riscos": {\n    "source": "iana"\n  },\n  "application/rlmi+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/rls-services+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rs"]\n  },\n  "application/route-apd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rapd"]\n  },\n  "application/route-s-tsid+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sls"]\n  },\n  "application/route-usd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rusd"]\n  },\n  "application/rpki-ghostbusters": {\n    "source": "iana",\n    "extensions": ["gbr"]\n  },\n  "application/rpki-manifest": {\n    "source": "iana",\n    "extensions": ["mft"]\n  },\n  "application/rpki-publication": {\n    "source": "iana"\n  },\n  "application/rpki-roa": {\n    "source": "iana",\n    "extensions": ["roa"]\n  },\n  "application/rpki-updown": {\n    "source": "iana"\n  },\n  "application/rsd+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["rsd"]\n  },\n  "application/rss+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["rss"]\n  },\n  "application/rtf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rtf"]\n  },\n  "application/rtploopback": {\n    "source": "iana"\n  },\n  "application/rtx": {\n    "source": "iana"\n  },\n  "application/samlassertion+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/samlmetadata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sarif+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sarif-external-properties+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sbe": {\n    "source": "iana"\n  },\n  "application/sbml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sbml"]\n  },\n  "application/scaip+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/scim+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/scvp-cv-request": {\n    "source": "iana",\n    "extensions": ["scq"]\n  },\n  "application/scvp-cv-response": {\n    "source": "iana",\n    "extensions": ["scs"]\n  },\n  "application/scvp-vp-request": {\n    "source": "iana",\n    "extensions": ["spq"]\n  },\n  "application/scvp-vp-response": {\n    "source": "iana",\n    "extensions": ["spp"]\n  },\n  "application/sdp": {\n    "source": "iana",\n    "extensions": ["sdp"]\n  },\n  "application/secevent+jwt": {\n    "source": "iana"\n  },\n  "application/senml+cbor": {\n    "source": "iana"\n  },\n  "application/senml+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/senml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["senmlx"]\n  },\n  "application/senml-etch+cbor": {\n    "source": "iana"\n  },\n  "application/senml-etch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/senml-exi": {\n    "source": "iana"\n  },\n  "application/sensml+cbor": {\n    "source": "iana"\n  },\n  "application/sensml+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sensml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sensmlx"]\n  },\n  "application/sensml-exi": {\n    "source": "iana"\n  },\n  "application/sep+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sep-exi": {\n    "source": "iana"\n  },\n  "application/session-info": {\n    "source": "iana"\n  },\n  "application/set-payment": {\n    "source": "iana"\n  },\n  "application/set-payment-initiation": {\n    "source": "iana",\n    "extensions": ["setpay"]\n  },\n  "application/set-registration": {\n    "source": "iana"\n  },\n  "application/set-registration-initiation": {\n    "source": "iana",\n    "extensions": ["setreg"]\n  },\n  "application/sgml": {\n    "source": "iana"\n  },\n  "application/sgml-open-catalog": {\n    "source": "iana"\n  },\n  "application/shf+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["shf"]\n  },\n  "application/sieve": {\n    "source": "iana",\n    "extensions": ["siv","sieve"]\n  },\n  "application/simple-filter+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/simple-message-summary": {\n    "source": "iana"\n  },\n  "application/simplesymbolcontainer": {\n    "source": "iana"\n  },\n  "application/sipc": {\n    "source": "iana"\n  },\n  "application/slate": {\n    "source": "iana"\n  },\n  "application/smil": {\n    "source": "iana"\n  },\n  "application/smil+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["smi","smil"]\n  },\n  "application/smpte336m": {\n    "source": "iana"\n  },\n  "application/soap+fastinfoset": {\n    "source": "iana"\n  },\n  "application/soap+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sparql-query": {\n    "source": "iana",\n    "extensions": ["rq"]\n  },\n  "application/sparql-results+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["srx"]\n  },\n  "application/spirits-event+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sql": {\n    "source": "iana"\n  },\n  "application/srgs": {\n    "source": "iana",\n    "extensions": ["gram"]\n  },\n  "application/srgs+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["grxml"]\n  },\n  "application/sru+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sru"]\n  },\n  "application/ssdl+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["ssdl"]\n  },\n  "application/ssml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ssml"]\n  },\n  "application/stix+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/swid+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["swidtag"]\n  },\n  "application/tamp-apex-update": {\n    "source": "iana"\n  },\n  "application/tamp-apex-update-confirm": {\n    "source": "iana"\n  },\n  "application/tamp-community-update": {\n    "source": "iana"\n  },\n  "application/tamp-community-update-confirm": {\n    "source": "iana"\n  },\n  "application/tamp-error": {\n    "source": "iana"\n  },\n  "application/tamp-sequence-adjust": {\n    "source": "iana"\n  },\n  "application/tamp-sequence-adjust-confirm": {\n    "source": "iana"\n  },\n  "application/tamp-status-query": {\n    "source": "iana"\n  },\n  "application/tamp-status-response": {\n    "source": "iana"\n  },\n  "application/tamp-update": {\n    "source": "iana"\n  },\n  "application/tamp-update-confirm": {\n    "source": "iana"\n  },\n  "application/tar": {\n    "compressible": true\n  },\n  "application/taxii+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/td+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/tei+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["tei","teicorpus"]\n  },\n  "application/tetra_isi": {\n    "source": "iana"\n  },\n  "application/thraud+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["tfi"]\n  },\n  "application/timestamp-query": {\n    "source": "iana"\n  },\n  "application/timestamp-reply": {\n    "source": "iana"\n  },\n  "application/timestamped-data": {\n    "source": "iana",\n    "extensions": ["tsd"]\n  },\n  "application/tlsrpt+gzip": {\n    "source": "iana"\n  },\n  "application/tlsrpt+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/tnauthlist": {\n    "source": "iana"\n  },\n  "application/toml": {\n    "compressible": true,\n    "extensions": ["toml"]\n  },\n  "application/trickle-ice-sdpfrag": {\n    "source": "iana"\n  },\n  "application/trig": {\n    "source": "iana"\n  },\n  "application/ttml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ttml"]\n  },\n  "application/tve-trigger": {\n    "source": "iana"\n  },\n  "application/tzif": {\n    "source": "iana"\n  },\n  "application/tzif-leap": {\n    "source": "iana"\n  },\n  "application/ubjson": {\n    "compressible": false,\n    "extensions": ["ubj"]\n  },\n  "application/ulpfec": {\n    "source": "iana"\n  },\n  "application/urc-grpsheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/urc-ressheet+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rsheet"]\n  },\n  "application/urc-targetdesc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["td"]\n  },\n  "application/urc-uisocketdesc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vcard+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vcard+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vemmi": {\n    "source": "iana"\n  },\n  "application/vividence.scriptfile": {\n    "source": "apache"\n  },\n  "application/vnd.1000minds.decision-model+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["1km"]\n  },\n  "application/vnd.3gpp-prose+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp-prose-pc3ch+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp-v2x-local-service-information": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.5gnas": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.access-transfer-events+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.bsf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.gmop+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.gtpc": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.interworking-data": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.lpp": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.mc-signalling-ear": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.mcdata-affiliation-command+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-payload": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.mcdata-service-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-signalling": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.mcdata-ue-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-user-profile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-affiliation-command+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-floor-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-location-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-mbms-usage-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-service-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-signed+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-ue-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-ue-init-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-user-profile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-affiliation-command+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-affiliation-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-location-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-mbms-usage-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-service-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-transmission-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-ue-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-user-profile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mid-call+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.ngap": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.pfcp": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.pic-bw-large": {\n    "source": "iana",\n    "extensions": ["plb"]\n  },\n  "application/vnd.3gpp.pic-bw-small": {\n    "source": "iana",\n    "extensions": ["psb"]\n  },\n  "application/vnd.3gpp.pic-bw-var": {\n    "source": "iana",\n    "extensions": ["pvb"]\n  },\n  "application/vnd.3gpp.s1ap": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.sms": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.sms+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.srvcc-ext+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.srvcc-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.state-and-event-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.ussd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp2.bcmcsinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp2.sms": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp2.tcap": {\n    "source": "iana",\n    "extensions": ["tcap"]\n  },\n  "application/vnd.3lightssoftware.imagescal": {\n    "source": "iana"\n  },\n  "application/vnd.3m.post-it-notes": {\n    "source": "iana",\n    "extensions": ["pwn"]\n  },\n  "application/vnd.accpac.simply.aso": {\n    "source": "iana",\n    "extensions": ["aso"]\n  },\n  "application/vnd.accpac.simply.imp": {\n    "source": "iana",\n    "extensions": ["imp"]\n  },\n  "application/vnd.acucobol": {\n    "source": "iana",\n    "extensions": ["acu"]\n  },\n  "application/vnd.acucorp": {\n    "source": "iana",\n    "extensions": ["atc","acutc"]\n  },\n  "application/vnd.adobe.air-application-installer-package+zip": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["air"]\n  },\n  "application/vnd.adobe.flash.movie": {\n    "source": "iana"\n  },\n  "application/vnd.adobe.formscentral.fcdt": {\n    "source": "iana",\n    "extensions": ["fcdt"]\n  },\n  "application/vnd.adobe.fxp": {\n    "source": "iana",\n    "extensions": ["fxp","fxpl"]\n  },\n  "application/vnd.adobe.partial-upload": {\n    "source": "iana"\n  },\n  "application/vnd.adobe.xdp+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdp"]\n  },\n  "application/vnd.adobe.xfdf": {\n    "source": "iana",\n    "extensions": ["xfdf"]\n  },\n  "application/vnd.aether.imp": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.afplinedata": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.afplinedata-pagedef": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.cmoca-cmresource": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.foca-charset": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.foca-codedfont": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.foca-codepage": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-cmtable": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-formdef": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-mediummap": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-objectcontainer": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-overlay": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-pagesegment": {\n    "source": "iana"\n  },\n  "application/vnd.ah-barcode": {\n    "source": "iana"\n  },\n  "application/vnd.ahead.space": {\n    "source": "iana",\n    "extensions": ["ahead"]\n  },\n  "application/vnd.airzip.filesecure.azf": {\n    "source": "iana",\n    "extensions": ["azf"]\n  },\n  "application/vnd.airzip.filesecure.azs": {\n    "source": "iana",\n    "extensions": ["azs"]\n  },\n  "application/vnd.amadeus+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.amazon.ebook": {\n    "source": "apache",\n    "extensions": ["azw"]\n  },\n  "application/vnd.amazon.mobi8-ebook": {\n    "source": "iana"\n  },\n  "application/vnd.americandynamics.acc": {\n    "source": "iana",\n    "extensions": ["acc"]\n  },\n  "application/vnd.amiga.ami": {\n    "source": "iana",\n    "extensions": ["ami"]\n  },\n  "application/vnd.amundsen.maze+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.android.ota": {\n    "source": "iana"\n  },\n  "application/vnd.android.package-archive": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["apk"]\n  },\n  "application/vnd.anki": {\n    "source": "iana"\n  },\n  "application/vnd.anser-web-certificate-issue-initiation": {\n    "source": "iana",\n    "extensions": ["cii"]\n  },\n  "application/vnd.anser-web-funds-transfer-initiation": {\n    "source": "apache",\n    "extensions": ["fti"]\n  },\n  "application/vnd.antix.game-component": {\n    "source": "iana",\n    "extensions": ["atx"]\n  },\n  "application/vnd.apache.thrift.binary": {\n    "source": "iana"\n  },\n  "application/vnd.apache.thrift.compact": {\n    "source": "iana"\n  },\n  "application/vnd.apache.thrift.json": {\n    "source": "iana"\n  },\n  "application/vnd.api+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.aplextor.warrp+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.apothekende.reservation+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.apple.installer+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mpkg"]\n  },\n  "application/vnd.apple.keynote": {\n    "source": "iana",\n    "extensions": ["key"]\n  },\n  "application/vnd.apple.mpegurl": {\n    "source": "iana",\n    "extensions": ["m3u8"]\n  },\n  "application/vnd.apple.numbers": {\n    "source": "iana",\n    "extensions": ["numbers"]\n  },\n  "application/vnd.apple.pages": {\n    "source": "iana",\n    "extensions": ["pages"]\n  },\n  "application/vnd.apple.pkpass": {\n    "compressible": false,\n    "extensions": ["pkpass"]\n  },\n  "application/vnd.arastra.swi": {\n    "source": "iana"\n  },\n  "application/vnd.aristanetworks.swi": {\n    "source": "iana",\n    "extensions": ["swi"]\n  },\n  "application/vnd.artisan+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.artsquare": {\n    "source": "iana"\n  },\n  "application/vnd.astraea-software.iota": {\n    "source": "iana",\n    "extensions": ["iota"]\n  },\n  "application/vnd.audiograph": {\n    "source": "iana",\n    "extensions": ["aep"]\n  },\n  "application/vnd.autopackage": {\n    "source": "iana"\n  },\n  "application/vnd.avalon+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.avistar+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.balsamiq.bmml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["bmml"]\n  },\n  "application/vnd.balsamiq.bmpr": {\n    "source": "iana"\n  },\n  "application/vnd.banana-accounting": {\n    "source": "iana"\n  },\n  "application/vnd.bbf.usp.error": {\n    "source": "iana"\n  },\n  "application/vnd.bbf.usp.msg": {\n    "source": "iana"\n  },\n  "application/vnd.bbf.usp.msg+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.bekitzur-stech+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.bint.med-content": {\n    "source": "iana"\n  },\n  "application/vnd.biopax.rdf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.blink-idb-value-wrapper": {\n    "source": "iana"\n  },\n  "application/vnd.blueice.multipass": {\n    "source": "iana",\n    "extensions": ["mpm"]\n  },\n  "application/vnd.bluetooth.ep.oob": {\n    "source": "iana"\n  },\n  "application/vnd.bluetooth.le.oob": {\n    "source": "iana"\n  },\n  "application/vnd.bmi": {\n    "source": "iana",\n    "extensions": ["bmi"]\n  },\n  "application/vnd.bpf": {\n    "source": "iana"\n  },\n  "application/vnd.bpf3": {\n    "source": "iana"\n  },\n  "application/vnd.businessobjects": {\n    "source": "iana",\n    "extensions": ["rep"]\n  },\n  "application/vnd.byu.uapi+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cab-jscript": {\n    "source": "iana"\n  },\n  "application/vnd.canon-cpdl": {\n    "source": "iana"\n  },\n  "application/vnd.canon-lips": {\n    "source": "iana"\n  },\n  "application/vnd.capasystems-pg+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cendio.thinlinc.clientconf": {\n    "source": "iana"\n  },\n  "application/vnd.century-systems.tcp_stream": {\n    "source": "iana"\n  },\n  "application/vnd.chemdraw+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["cdxml"]\n  },\n  "application/vnd.chess-pgn": {\n    "source": "iana"\n  },\n  "application/vnd.chipnuts.karaoke-mmd": {\n    "source": "iana",\n    "extensions": ["mmd"]\n  },\n  "application/vnd.ciedi": {\n    "source": "iana"\n  },\n  "application/vnd.cinderella": {\n    "source": "iana",\n    "extensions": ["cdy"]\n  },\n  "application/vnd.cirpack.isdn-ext": {\n    "source": "iana"\n  },\n  "application/vnd.citationstyles.style+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["csl"]\n  },\n  "application/vnd.claymore": {\n    "source": "iana",\n    "extensions": ["cla"]\n  },\n  "application/vnd.cloanto.rp9": {\n    "source": "iana",\n    "extensions": ["rp9"]\n  },\n  "application/vnd.clonk.c4group": {\n    "source": "iana",\n    "extensions": ["c4g","c4d","c4f","c4p","c4u"]\n  },\n  "application/vnd.cluetrust.cartomobile-config": {\n    "source": "iana",\n    "extensions": ["c11amc"]\n  },\n  "application/vnd.cluetrust.cartomobile-config-pkg": {\n    "source": "iana",\n    "extensions": ["c11amz"]\n  },\n  "application/vnd.coffeescript": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.document": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.document-template": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.presentation": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.presentation-template": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.spreadsheet": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.spreadsheet-template": {\n    "source": "iana"\n  },\n  "application/vnd.collection+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.collection.doc+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.collection.next+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.comicbook+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.comicbook-rar": {\n    "source": "iana"\n  },\n  "application/vnd.commerce-battelle": {\n    "source": "iana"\n  },\n  "application/vnd.commonspace": {\n    "source": "iana",\n    "extensions": ["csp"]\n  },\n  "application/vnd.contact.cmsg": {\n    "source": "iana",\n    "extensions": ["cdbcmsg"]\n  },\n  "application/vnd.coreos.ignition+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cosmocaller": {\n    "source": "iana",\n    "extensions": ["cmc"]\n  },\n  "application/vnd.crick.clicker": {\n    "source": "iana",\n    "extensions": ["clkx"]\n  },\n  "application/vnd.crick.clicker.keyboard": {\n    "source": "iana",\n    "extensions": ["clkk"]\n  },\n  "application/vnd.crick.clicker.palette": {\n    "source": "iana",\n    "extensions": ["clkp"]\n  },\n  "application/vnd.crick.clicker.template": {\n    "source": "iana",\n    "extensions": ["clkt"]\n  },\n  "application/vnd.crick.clicker.wordbank": {\n    "source": "iana",\n    "extensions": ["clkw"]\n  },\n  "application/vnd.criticaltools.wbs+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wbs"]\n  },\n  "application/vnd.cryptii.pipe+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.crypto-shade-file": {\n    "source": "iana"\n  },\n  "application/vnd.cryptomator.encrypted": {\n    "source": "iana"\n  },\n  "application/vnd.cryptomator.vault": {\n    "source": "iana"\n  },\n  "application/vnd.ctc-posml": {\n    "source": "iana",\n    "extensions": ["pml"]\n  },\n  "application/vnd.ctct.ws+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cups-pdf": {\n    "source": "iana"\n  },\n  "application/vnd.cups-postscript": {\n    "source": "iana"\n  },\n  "application/vnd.cups-ppd": {\n    "source": "iana",\n    "extensions": ["ppd"]\n  },\n  "application/vnd.cups-raster": {\n    "source": "iana"\n  },\n  "application/vnd.cups-raw": {\n    "source": "iana"\n  },\n  "application/vnd.curl": {\n    "source": "iana"\n  },\n  "application/vnd.curl.car": {\n    "source": "apache",\n    "extensions": ["car"]\n  },\n  "application/vnd.curl.pcurl": {\n    "source": "apache",\n    "extensions": ["pcurl"]\n  },\n  "application/vnd.cyan.dean.root+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cybank": {\n    "source": "iana"\n  },\n  "application/vnd.cyclonedx+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cyclonedx+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.d2l.coursepackage1p0+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.d3m-dataset": {\n    "source": "iana"\n  },\n  "application/vnd.d3m-problem": {\n    "source": "iana"\n  },\n  "application/vnd.dart": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dart"]\n  },\n  "application/vnd.data-vision.rdz": {\n    "source": "iana",\n    "extensions": ["rdz"]\n  },\n  "application/vnd.datapackage+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dataresource+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dbf": {\n    "source": "iana",\n    "extensions": ["dbf"]\n  },\n  "application/vnd.debian.binary-package": {\n    "source": "iana"\n  },\n  "application/vnd.dece.data": {\n    "source": "iana",\n    "extensions": ["uvf","uvvf","uvd","uvvd"]\n  },\n  "application/vnd.dece.ttml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["uvt","uvvt"]\n  },\n  "application/vnd.dece.unspecified": {\n    "source": "iana",\n    "extensions": ["uvx","uvvx"]\n  },\n  "application/vnd.dece.zip": {\n    "source": "iana",\n    "extensions": ["uvz","uvvz"]\n  },\n  "application/vnd.denovo.fcselayout-link": {\n    "source": "iana",\n    "extensions": ["fe_launch"]\n  },\n  "application/vnd.desmume.movie": {\n    "source": "iana"\n  },\n  "application/vnd.dir-bi.plate-dl-nosuffix": {\n    "source": "iana"\n  },\n  "application/vnd.dm.delegation+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dna": {\n    "source": "iana",\n    "extensions": ["dna"]\n  },\n  "application/vnd.document+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dolby.mlp": {\n    "source": "apache",\n    "extensions": ["mlp"]\n  },\n  "application/vnd.dolby.mobile.1": {\n    "source": "iana"\n  },\n  "application/vnd.dolby.mobile.2": {\n    "source": "iana"\n  },\n  "application/vnd.doremir.scorecloud-binary-document": {\n    "source": "iana"\n  },\n  "application/vnd.dpgraph": {\n    "source": "iana",\n    "extensions": ["dpg"]\n  },\n  "application/vnd.dreamfactory": {\n    "source": "iana",\n    "extensions": ["dfac"]\n  },\n  "application/vnd.drive+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ds-keypoint": {\n    "source": "apache",\n    "extensions": ["kpxx"]\n  },\n  "application/vnd.dtg.local": {\n    "source": "iana"\n  },\n  "application/vnd.dtg.local.flash": {\n    "source": "iana"\n  },\n  "application/vnd.dtg.local.html": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ait": {\n    "source": "iana",\n    "extensions": ["ait"]\n  },\n  "application/vnd.dvb.dvbisl+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.dvbj": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.esgcontainer": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcdftnotifaccess": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcesgaccess": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcesgaccess2": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcesgpdd": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcroaming": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.iptv.alfec-base": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.iptv.alfec-enhancement": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.notif-aggregate-root+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-container+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-generic+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-ia-msglist+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-ia-registration-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-ia-registration-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-init+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.pfr": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.service": {\n    "source": "iana",\n    "extensions": ["svc"]\n  },\n  "application/vnd.dxr": {\n    "source": "iana"\n  },\n  "application/vnd.dynageo": {\n    "source": "iana",\n    "extensions": ["geo"]\n  },\n  "application/vnd.dzr": {\n    "source": "iana"\n  },\n  "application/vnd.easykaraoke.cdgdownload": {\n    "source": "iana"\n  },\n  "application/vnd.ecdis-update": {\n    "source": "iana"\n  },\n  "application/vnd.ecip.rlp": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.chart": {\n    "source": "iana",\n    "extensions": ["mag"]\n  },\n  "application/vnd.ecowin.filerequest": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.fileupdate": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.series": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.seriesrequest": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.seriesupdate": {\n    "source": "iana"\n  },\n  "application/vnd.efi.img": {\n    "source": "iana"\n  },\n  "application/vnd.efi.iso": {\n    "source": "iana"\n  },\n  "application/vnd.emclient.accessrequest+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.enliven": {\n    "source": "iana",\n    "extensions": ["nml"]\n  },\n  "application/vnd.enphase.envoy": {\n    "source": "iana"\n  },\n  "application/vnd.eprints.data+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.epson.esf": {\n    "source": "iana",\n    "extensions": ["esf"]\n  },\n  "application/vnd.epson.msf": {\n    "source": "iana",\n    "extensions": ["msf"]\n  },\n  "application/vnd.epson.quickanime": {\n    "source": "iana",\n    "extensions": ["qam"]\n  },\n  "application/vnd.epson.salt": {\n    "source": "iana",\n    "extensions": ["slt"]\n  },\n  "application/vnd.epson.ssf": {\n    "source": "iana",\n    "extensions": ["ssf"]\n  },\n  "application/vnd.ericsson.quickcall": {\n    "source": "iana"\n  },\n  "application/vnd.espass-espass+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.eszigno3+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["es3","et3"]\n  },\n  "application/vnd.etsi.aoc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.asic-e+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.etsi.asic-s+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.etsi.cug+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvcommand+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvdiscovery+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsad-bc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsad-cod+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsad-npvr+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvservice+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsync+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvueprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.mcid+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.mheg5": {\n    "source": "iana"\n  },\n  "application/vnd.etsi.overload-control-policy-dataset+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.pstn+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.sci+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.simservs+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.timestamp-token": {\n    "source": "iana"\n  },\n  "application/vnd.etsi.tsl+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.tsl.der": {\n    "source": "iana"\n  },\n  "application/vnd.eudora.data": {\n    "source": "iana"\n  },\n  "application/vnd.evolv.ecig.profile": {\n    "source": "iana"\n  },\n  "application/vnd.evolv.ecig.settings": {\n    "source": "iana"\n  },\n  "application/vnd.evolv.ecig.theme": {\n    "source": "iana"\n  },\n  "application/vnd.exstream-empower+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.exstream-package": {\n    "source": "iana"\n  },\n  "application/vnd.ezpix-album": {\n    "source": "iana",\n    "extensions": ["ez2"]\n  },\n  "application/vnd.ezpix-package": {\n    "source": "iana",\n    "extensions": ["ez3"]\n  },\n  "application/vnd.f-secure.mobile": {\n    "source": "iana"\n  },\n  "application/vnd.fastcopy-disk-image": {\n    "source": "iana"\n  },\n  "application/vnd.fdf": {\n    "source": "iana",\n    "extensions": ["fdf"]\n  },\n  "application/vnd.fdsn.mseed": {\n    "source": "iana",\n    "extensions": ["mseed"]\n  },\n  "application/vnd.fdsn.seed": {\n    "source": "iana",\n    "extensions": ["seed","dataless"]\n  },\n  "application/vnd.ffsns": {\n    "source": "iana"\n  },\n  "application/vnd.ficlab.flb+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.filmit.zfc": {\n    "source": "iana"\n  },\n  "application/vnd.fints": {\n    "source": "iana"\n  },\n  "application/vnd.firemonkeys.cloudcell": {\n    "source": "iana"\n  },\n  "application/vnd.flographit": {\n    "source": "iana",\n    "extensions": ["gph"]\n  },\n  "application/vnd.fluxtime.clip": {\n    "source": "iana",\n    "extensions": ["ftc"]\n  },\n  "application/vnd.font-fontforge-sfd": {\n    "source": "iana"\n  },\n  "application/vnd.framemaker": {\n    "source": "iana",\n    "extensions": ["fm","frame","maker","book"]\n  },\n  "application/vnd.frogans.fnc": {\n    "source": "iana",\n    "extensions": ["fnc"]\n  },\n  "application/vnd.frogans.ltf": {\n    "source": "iana",\n    "extensions": ["ltf"]\n  },\n  "application/vnd.fsc.weblaunch": {\n    "source": "iana",\n    "extensions": ["fsc"]\n  },\n  "application/vnd.fujifilm.fb.docuworks": {\n    "source": "iana"\n  },\n  "application/vnd.fujifilm.fb.docuworks.binder": {\n    "source": "iana"\n  },\n  "application/vnd.fujifilm.fb.docuworks.container": {\n    "source": "iana"\n  },\n  "application/vnd.fujifilm.fb.jfi+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.fujitsu.oasys": {\n    "source": "iana",\n    "extensions": ["oas"]\n  },\n  "application/vnd.fujitsu.oasys2": {\n    "source": "iana",\n    "extensions": ["oa2"]\n  },\n  "application/vnd.fujitsu.oasys3": {\n    "source": "iana",\n    "extensions": ["oa3"]\n  },\n  "application/vnd.fujitsu.oasysgp": {\n    "source": "iana",\n    "extensions": ["fg5"]\n  },\n  "application/vnd.fujitsu.oasysprs": {\n    "source": "iana",\n    "extensions": ["bh2"]\n  },\n  "application/vnd.fujixerox.art-ex": {\n    "source": "iana"\n  },\n  "application/vnd.fujixerox.art4": {\n    "source": "iana"\n  },\n  "application/vnd.fujixerox.ddd": {\n    "source": "iana",\n    "extensions": ["ddd"]\n  },\n  "application/vnd.fujixerox.docuworks": {\n    "source": "iana",\n    "extensions": ["xdw"]\n  },\n  "application/vnd.fujixerox.docuworks.binder": {\n    "source": "iana",\n    "extensions": ["xbd"]\n  },\n  "application/vnd.fujixerox.docuworks.container": {\n    "source": "iana"\n  },\n  "application/vnd.fujixerox.hbpl": {\n    "source": "iana"\n  },\n  "application/vnd.fut-misnet": {\n    "source": "iana"\n  },\n  "application/vnd.futoin+cbor": {\n    "source": "iana"\n  },\n  "application/vnd.futoin+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.fuzzysheet": {\n    "source": "iana",\n    "extensions": ["fzs"]\n  },\n  "application/vnd.genomatix.tuxedo": {\n    "source": "iana",\n    "extensions": ["txd"]\n  },\n  "application/vnd.gentics.grd+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.geo+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.geocube+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.geogebra.file": {\n    "source": "iana",\n    "extensions": ["ggb"]\n  },\n  "application/vnd.geogebra.slides": {\n    "source": "iana"\n  },\n  "application/vnd.geogebra.tool": {\n    "source": "iana",\n    "extensions": ["ggt"]\n  },\n  "application/vnd.geometry-explorer": {\n    "source": "iana",\n    "extensions": ["gex","gre"]\n  },\n  "application/vnd.geonext": {\n    "source": "iana",\n    "extensions": ["gxt"]\n  },\n  "application/vnd.geoplan": {\n    "source": "iana",\n    "extensions": ["g2w"]\n  },\n  "application/vnd.geospace": {\n    "source": "iana",\n    "extensions": ["g3w"]\n  },\n  "application/vnd.gerber": {\n    "source": "iana"\n  },\n  "application/vnd.globalplatform.card-content-mgt": {\n    "source": "iana"\n  },\n  "application/vnd.globalplatform.card-content-mgt-response": {\n    "source": "iana"\n  },\n  "application/vnd.gmx": {\n    "source": "iana",\n    "extensions": ["gmx"]\n  },\n  "application/vnd.google-apps.document": {\n    "compressible": false,\n    "extensions": ["gdoc"]\n  },\n  "application/vnd.google-apps.presentation": {\n    "compressible": false,\n    "extensions": ["gslides"]\n  },\n  "application/vnd.google-apps.spreadsheet": {\n    "compressible": false,\n    "extensions": ["gsheet"]\n  },\n  "application/vnd.google-earth.kml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["kml"]\n  },\n  "application/vnd.google-earth.kmz": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["kmz"]\n  },\n  "application/vnd.gov.sk.e-form+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.gov.sk.e-form+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.gov.sk.xmldatacontainer+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.grafeq": {\n    "source": "iana",\n    "extensions": ["gqf","gqs"]\n  },\n  "application/vnd.gridmp": {\n    "source": "iana"\n  },\n  "application/vnd.groove-account": {\n    "source": "iana",\n    "extensions": ["gac"]\n  },\n  "application/vnd.groove-help": {\n    "source": "iana",\n    "extensions": ["ghf"]\n  },\n  "application/vnd.groove-identity-message": {\n    "source": "iana",\n    "extensions": ["gim"]\n  },\n  "application/vnd.groove-injector": {\n    "source": "iana",\n    "extensions": ["grv"]\n  },\n  "application/vnd.groove-tool-message": {\n    "source": "iana",\n    "extensions": ["gtm"]\n  },\n  "application/vnd.groove-tool-template": {\n    "source": "iana",\n    "extensions": ["tpl"]\n  },\n  "application/vnd.groove-vcard": {\n    "source": "iana",\n    "extensions": ["vcg"]\n  },\n  "application/vnd.hal+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hal+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["hal"]\n  },\n  "application/vnd.handheld-entertainment+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["zmm"]\n  },\n  "application/vnd.hbci": {\n    "source": "iana",\n    "extensions": ["hbci"]\n  },\n  "application/vnd.hc+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hcl-bireports": {\n    "source": "iana"\n  },\n  "application/vnd.hdt": {\n    "source": "iana"\n  },\n  "application/vnd.heroku+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hhe.lesson-player": {\n    "source": "iana",\n    "extensions": ["les"]\n  },\n  "application/vnd.hp-hpgl": {\n    "source": "iana",\n    "extensions": ["hpgl"]\n  },\n  "application/vnd.hp-hpid": {\n    "source": "iana",\n    "extensions": ["hpid"]\n  },\n  "application/vnd.hp-hps": {\n    "source": "iana",\n    "extensions": ["hps"]\n  },\n  "application/vnd.hp-jlyt": {\n    "source": "iana",\n    "extensions": ["jlt"]\n  },\n  "application/vnd.hp-pcl": {\n    "source": "iana",\n    "extensions": ["pcl"]\n  },\n  "application/vnd.hp-pclxl": {\n    "source": "iana",\n    "extensions": ["pclxl"]\n  },\n  "application/vnd.httphone": {\n    "source": "iana"\n  },\n  "application/vnd.hydrostatix.sof-data": {\n    "source": "iana",\n    "extensions": ["sfd-hdstx"]\n  },\n  "application/vnd.hyper+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hyper-item+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hyperdrive+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hzn-3d-crossword": {\n    "source": "iana"\n  },\n  "application/vnd.ibm.afplinedata": {\n    "source": "iana"\n  },\n  "application/vnd.ibm.electronic-media": {\n    "source": "iana"\n  },\n  "application/vnd.ibm.minipay": {\n    "source": "iana",\n    "extensions": ["mpy"]\n  },\n  "application/vnd.ibm.modcap": {\n    "source": "iana",\n    "extensions": ["afp","listafp","list3820"]\n  },\n  "application/vnd.ibm.rights-management": {\n    "source": "iana",\n    "extensions": ["irm"]\n  },\n  "application/vnd.ibm.secure-container": {\n    "source": "iana",\n    "extensions": ["sc"]\n  },\n  "application/vnd.iccprofile": {\n    "source": "iana",\n    "extensions": ["icc","icm"]\n  },\n  "application/vnd.ieee.1905": {\n    "source": "iana"\n  },\n  "application/vnd.igloader": {\n    "source": "iana",\n    "extensions": ["igl"]\n  },\n  "application/vnd.imagemeter.folder+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.imagemeter.image+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.immervision-ivp": {\n    "source": "iana",\n    "extensions": ["ivp"]\n  },\n  "application/vnd.immervision-ivu": {\n    "source": "iana",\n    "extensions": ["ivu"]\n  },\n  "application/vnd.ims.imsccv1p1": {\n    "source": "iana"\n  },\n  "application/vnd.ims.imsccv1p2": {\n    "source": "iana"\n  },\n  "application/vnd.ims.imsccv1p3": {\n    "source": "iana"\n  },\n  "application/vnd.ims.lis.v2.result+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolconsumerprofile+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolproxy+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolproxy.id+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolsettings+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolsettings.simple+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.informedcontrol.rms+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.informix-visionary": {\n    "source": "iana"\n  },\n  "application/vnd.infotech.project": {\n    "source": "iana"\n  },\n  "application/vnd.infotech.project+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.innopath.wamp.notification": {\n    "source": "iana"\n  },\n  "application/vnd.insors.igm": {\n    "source": "iana",\n    "extensions": ["igm"]\n  },\n  "application/vnd.intercon.formnet": {\n    "source": "iana",\n    "extensions": ["xpw","xpx"]\n  },\n  "application/vnd.intergeo": {\n    "source": "iana",\n    "extensions": ["i2g"]\n  },\n  "application/vnd.intertrust.digibox": {\n    "source": "iana"\n  },\n  "application/vnd.intertrust.nncp": {\n    "source": "iana"\n  },\n  "application/vnd.intu.qbo": {\n    "source": "iana",\n    "extensions": ["qbo"]\n  },\n  "application/vnd.intu.qfx": {\n    "source": "iana",\n    "extensions": ["qfx"]\n  },\n  "application/vnd.iptc.g2.catalogitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.conceptitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.knowledgeitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.newsitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.newsmessage+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.packageitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.planningitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ipunplugged.rcprofile": {\n    "source": "iana",\n    "extensions": ["rcprofile"]\n  },\n  "application/vnd.irepository.package+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["irp"]\n  },\n  "application/vnd.is-xpr": {\n    "source": "iana",\n    "extensions": ["xpr"]\n  },\n  "application/vnd.isac.fcs": {\n    "source": "iana",\n    "extensions": ["fcs"]\n  },\n  "application/vnd.iso11783-10+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.jam": {\n    "source": "iana",\n    "extensions": ["jam"]\n  },\n  "application/vnd.japannet-directory-service": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-jpnstore-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-payment-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-registration": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-registration-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-setstore-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-verification": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-verification-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.jcp.javame.midlet-rms": {\n    "source": "iana",\n    "extensions": ["rms"]\n  },\n  "application/vnd.jisp": {\n    "source": "iana",\n    "extensions": ["jisp"]\n  },\n  "application/vnd.joost.joda-archive": {\n    "source": "iana",\n    "extensions": ["joda"]\n  },\n  "application/vnd.jsk.isdn-ngn": {\n    "source": "iana"\n  },\n  "application/vnd.kahootz": {\n    "source": "iana",\n    "extensions": ["ktz","ktr"]\n  },\n  "application/vnd.kde.karbon": {\n    "source": "iana",\n    "extensions": ["karbon"]\n  },\n  "application/vnd.kde.kchart": {\n    "source": "iana",\n    "extensions": ["chrt"]\n  },\n  "application/vnd.kde.kformula": {\n    "source": "iana",\n    "extensions": ["kfo"]\n  },\n  "application/vnd.kde.kivio": {\n    "source": "iana",\n    "extensions": ["flw"]\n  },\n  "application/vnd.kde.kontour": {\n    "source": "iana",\n    "extensions": ["kon"]\n  },\n  "application/vnd.kde.kpresenter": {\n    "source": "iana",\n    "extensions": ["kpr","kpt"]\n  },\n  "application/vnd.kde.kspread": {\n    "source": "iana",\n    "extensions": ["ksp"]\n  },\n  "application/vnd.kde.kword": {\n    "source": "iana",\n    "extensions": ["kwd","kwt"]\n  },\n  "application/vnd.kenameaapp": {\n    "source": "iana",\n    "extensions": ["htke"]\n  },\n  "application/vnd.kidspiration": {\n    "source": "iana",\n    "extensions": ["kia"]\n  },\n  "application/vnd.kinar": {\n    "source": "iana",\n    "extensions": ["kne","knp"]\n  },\n  "application/vnd.koan": {\n    "source": "iana",\n    "extensions": ["skp","skd","skt","skm"]\n  },\n  "application/vnd.kodak-descriptor": {\n    "source": "iana",\n    "extensions": ["sse"]\n  },\n  "application/vnd.las": {\n    "source": "iana"\n  },\n  "application/vnd.las.las+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.las.las+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lasxml"]\n  },\n  "application/vnd.laszip": {\n    "source": "iana"\n  },\n  "application/vnd.leap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.liberty-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.llamagraphics.life-balance.desktop": {\n    "source": "iana",\n    "extensions": ["lbd"]\n  },\n  "application/vnd.llamagraphics.life-balance.exchange+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lbe"]\n  },\n  "application/vnd.logipipe.circuit+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.loom": {\n    "source": "iana"\n  },\n  "application/vnd.lotus-1-2-3": {\n    "source": "iana",\n    "extensions": ["123"]\n  },\n  "application/vnd.lotus-approach": {\n    "source": "iana",\n    "extensions": ["apr"]\n  },\n  "application/vnd.lotus-freelance": {\n    "source": "iana",\n    "extensions": ["pre"]\n  },\n  "application/vnd.lotus-notes": {\n    "source": "iana",\n    "extensions": ["nsf"]\n  },\n  "application/vnd.lotus-organizer": {\n    "source": "iana",\n    "extensions": ["org"]\n  },\n  "application/vnd.lotus-screencam": {\n    "source": "iana",\n    "extensions": ["scm"]\n  },\n  "application/vnd.lotus-wordpro": {\n    "source": "iana",\n    "extensions": ["lwp"]\n  },\n  "application/vnd.macports.portpkg": {\n    "source": "iana",\n    "extensions": ["portpkg"]\n  },\n  "application/vnd.mapbox-vector-tile": {\n    "source": "iana",\n    "extensions": ["mvt"]\n  },\n  "application/vnd.marlin.drm.actiontoken+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.marlin.drm.conftoken+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.marlin.drm.license+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.marlin.drm.mdcf": {\n    "source": "iana"\n  },\n  "application/vnd.mason+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.maxmind.maxmind-db": {\n    "source": "iana"\n  },\n  "application/vnd.mcd": {\n    "source": "iana",\n    "extensions": ["mcd"]\n  },\n  "application/vnd.medcalcdata": {\n    "source": "iana",\n    "extensions": ["mc1"]\n  },\n  "application/vnd.mediastation.cdkey": {\n    "source": "iana",\n    "extensions": ["cdkey"]\n  },\n  "application/vnd.meridian-slingshot": {\n    "source": "iana"\n  },\n  "application/vnd.mfer": {\n    "source": "iana",\n    "extensions": ["mwf"]\n  },\n  "application/vnd.mfmp": {\n    "source": "iana",\n    "extensions": ["mfm"]\n  },\n  "application/vnd.micro+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.micrografx.flo": {\n    "source": "iana",\n    "extensions": ["flo"]\n  },\n  "application/vnd.micrografx.igx": {\n    "source": "iana",\n    "extensions": ["igx"]\n  },\n  "application/vnd.microsoft.portable-executable": {\n    "source": "iana"\n  },\n  "application/vnd.microsoft.windows.thumbnail-cache": {\n    "source": "iana"\n  },\n  "application/vnd.miele+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.mif": {\n    "source": "iana",\n    "extensions": ["mif"]\n  },\n  "application/vnd.minisoft-hp3000-save": {\n    "source": "iana"\n  },\n  "application/vnd.mitsubishi.misty-guard.trustweb": {\n    "source": "iana"\n  },\n  "application/vnd.mobius.daf": {\n    "source": "iana",\n    "extensions": ["daf"]\n  },\n  "application/vnd.mobius.dis": {\n    "source": "iana",\n    "extensions": ["dis"]\n  },\n  "application/vnd.mobius.mbk": {\n    "source": "iana",\n    "extensions": ["mbk"]\n  },\n  "application/vnd.mobius.mqy": {\n    "source": "iana",\n    "extensions": ["mqy"]\n  },\n  "application/vnd.mobius.msl": {\n    "source": "iana",\n    "extensions": ["msl"]\n  },\n  "application/vnd.mobius.plc": {\n    "source": "iana",\n    "extensions": ["plc"]\n  },\n  "application/vnd.mobius.txf": {\n    "source": "iana",\n    "extensions": ["txf"]\n  },\n  "application/vnd.mophun.application": {\n    "source": "iana",\n    "extensions": ["mpn"]\n  },\n  "application/vnd.mophun.certificate": {\n    "source": "iana",\n    "extensions": ["mpc"]\n  },\n  "application/vnd.motorola.flexsuite": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.adsi": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.fis": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.gotap": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.kmr": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.ttc": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.wem": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.iprm": {\n    "source": "iana"\n  },\n  "application/vnd.mozilla.xul+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xul"]\n  },\n  "application/vnd.ms-3mfdocument": {\n    "source": "iana"\n  },\n  "application/vnd.ms-artgalry": {\n    "source": "iana",\n    "extensions": ["cil"]\n  },\n  "application/vnd.ms-asf": {\n    "source": "iana"\n  },\n  "application/vnd.ms-cab-compressed": {\n    "source": "iana",\n    "extensions": ["cab"]\n  },\n  "application/vnd.ms-color.iccprofile": {\n    "source": "apache"\n  },\n  "application/vnd.ms-excel": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["xls","xlm","xla","xlc","xlt","xlw"]\n  },\n  "application/vnd.ms-excel.addin.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xlam"]\n  },\n  "application/vnd.ms-excel.sheet.binary.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xlsb"]\n  },\n  "application/vnd.ms-excel.sheet.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xlsm"]\n  },\n  "application/vnd.ms-excel.template.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xltm"]\n  },\n  "application/vnd.ms-fontobject": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["eot"]\n  },\n  "application/vnd.ms-htmlhelp": {\n    "source": "iana",\n    "extensions": ["chm"]\n  },\n  "application/vnd.ms-ims": {\n    "source": "iana",\n    "extensions": ["ims"]\n  },\n  "application/vnd.ms-lrm": {\n    "source": "iana",\n    "extensions": ["lrm"]\n  },\n  "application/vnd.ms-office.activex+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-officetheme": {\n    "source": "iana",\n    "extensions": ["thmx"]\n  },\n  "application/vnd.ms-opentype": {\n    "source": "apache",\n    "compressible": true\n  },\n  "application/vnd.ms-outlook": {\n    "compressible": false,\n    "extensions": ["msg"]\n  },\n  "application/vnd.ms-package.obfuscated-opentype": {\n    "source": "apache"\n  },\n  "application/vnd.ms-pki.seccat": {\n    "source": "apache",\n    "extensions": ["cat"]\n  },\n  "application/vnd.ms-pki.stl": {\n    "source": "apache",\n    "extensions": ["stl"]\n  },\n  "application/vnd.ms-playready.initiator+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-powerpoint": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ppt","pps","pot"]\n  },\n  "application/vnd.ms-powerpoint.addin.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["ppam"]\n  },\n  "application/vnd.ms-powerpoint.presentation.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["pptm"]\n  },\n  "application/vnd.ms-powerpoint.slide.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["sldm"]\n  },\n  "application/vnd.ms-powerpoint.slideshow.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["ppsm"]\n  },\n  "application/vnd.ms-powerpoint.template.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["potm"]\n  },\n  "application/vnd.ms-printdevicecapabilities+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-printing.printticket+xml": {\n    "source": "apache",\n    "compressible": true\n  },\n  "application/vnd.ms-printschematicket+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-project": {\n    "source": "iana",\n    "extensions": ["mpp","mpt"]\n  },\n  "application/vnd.ms-tnef": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.devicepairing": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.nwprinting.oob": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.printerpairing": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.wsd.oob": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.lic-chlg-req": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.lic-resp": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.meter-chlg-req": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.meter-resp": {\n    "source": "iana"\n  },\n  "application/vnd.ms-word.document.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["docm"]\n  },\n  "application/vnd.ms-word.template.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["dotm"]\n  },\n  "application/vnd.ms-works": {\n    "source": "iana",\n    "extensions": ["wps","wks","wcm","wdb"]\n  },\n  "application/vnd.ms-wpl": {\n    "source": "iana",\n    "extensions": ["wpl"]\n  },\n  "application/vnd.ms-xpsdocument": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["xps"]\n  },\n  "application/vnd.msa-disk-image": {\n    "source": "iana"\n  },\n  "application/vnd.mseq": {\n    "source": "iana",\n    "extensions": ["mseq"]\n  },\n  "application/vnd.msign": {\n    "source": "iana"\n  },\n  "application/vnd.multiad.creator": {\n    "source": "iana"\n  },\n  "application/vnd.multiad.creator.cif": {\n    "source": "iana"\n  },\n  "application/vnd.music-niff": {\n    "source": "iana"\n  },\n  "application/vnd.musician": {\n    "source": "iana",\n    "extensions": ["mus"]\n  },\n  "application/vnd.muvee.style": {\n    "source": "iana",\n    "extensions": ["msty"]\n  },\n  "application/vnd.mynfc": {\n    "source": "iana",\n    "extensions": ["taglet"]\n  },\n  "application/vnd.ncd.control": {\n    "source": "iana"\n  },\n  "application/vnd.ncd.reference": {\n    "source": "iana"\n  },\n  "application/vnd.nearst.inv+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nebumind.line": {\n    "source": "iana"\n  },\n  "application/vnd.nervana": {\n    "source": "iana"\n  },\n  "application/vnd.netfpx": {\n    "source": "iana"\n  },\n  "application/vnd.neurolanguage.nlu": {\n    "source": "iana",\n    "extensions": ["nlu"]\n  },\n  "application/vnd.nimn": {\n    "source": "iana"\n  },\n  "application/vnd.nintendo.nitro.rom": {\n    "source": "iana"\n  },\n  "application/vnd.nintendo.snes.rom": {\n    "source": "iana"\n  },\n  "application/vnd.nitf": {\n    "source": "iana",\n    "extensions": ["ntf","nitf"]\n  },\n  "application/vnd.noblenet-directory": {\n    "source": "iana",\n    "extensions": ["nnd"]\n  },\n  "application/vnd.noblenet-sealer": {\n    "source": "iana",\n    "extensions": ["nns"]\n  },\n  "application/vnd.noblenet-web": {\n    "source": "iana",\n    "extensions": ["nnw"]\n  },\n  "application/vnd.nokia.catalogs": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.conml+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.conml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.iptv.config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.isds-radio-presets": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.landmark+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.landmark+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.landmarkcollection+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.n-gage.ac+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ac"]\n  },\n  "application/vnd.nokia.n-gage.data": {\n    "source": "iana",\n    "extensions": ["ngdat"]\n  },\n  "application/vnd.nokia.n-gage.symbian.install": {\n    "source": "iana",\n    "extensions": ["n-gage"]\n  },\n  "application/vnd.nokia.ncd": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.pcd+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.pcd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.radio-preset": {\n    "source": "iana",\n    "extensions": ["rpst"]\n  },\n  "application/vnd.nokia.radio-presets": {\n    "source": "iana",\n    "extensions": ["rpss"]\n  },\n  "application/vnd.novadigm.edm": {\n    "source": "iana",\n    "extensions": ["edm"]\n  },\n  "application/vnd.novadigm.edx": {\n    "source": "iana",\n    "extensions": ["edx"]\n  },\n  "application/vnd.novadigm.ext": {\n    "source": "iana",\n    "extensions": ["ext"]\n  },\n  "application/vnd.ntt-local.content-share": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.file-transfer": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.ogw_remote-access": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.sip-ta_remote": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.sip-ta_tcp_stream": {\n    "source": "iana"\n  },\n  "application/vnd.oasis.opendocument.chart": {\n    "source": "iana",\n    "extensions": ["odc"]\n  },\n  "application/vnd.oasis.opendocument.chart-template": {\n    "source": "iana",\n    "extensions": ["otc"]\n  },\n  "application/vnd.oasis.opendocument.database": {\n    "source": "iana",\n    "extensions": ["odb"]\n  },\n  "application/vnd.oasis.opendocument.formula": {\n    "source": "iana",\n    "extensions": ["odf"]\n  },\n  "application/vnd.oasis.opendocument.formula-template": {\n    "source": "iana",\n    "extensions": ["odft"]\n  },\n  "application/vnd.oasis.opendocument.graphics": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["odg"]\n  },\n  "application/vnd.oasis.opendocument.graphics-template": {\n    "source": "iana",\n    "extensions": ["otg"]\n  },\n  "application/vnd.oasis.opendocument.image": {\n    "source": "iana",\n    "extensions": ["odi"]\n  },\n  "application/vnd.oasis.opendocument.image-template": {\n    "source": "iana",\n    "extensions": ["oti"]\n  },\n  "application/vnd.oasis.opendocument.presentation": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["odp"]\n  },\n  "application/vnd.oasis.opendocument.presentation-template": {\n    "source": "iana",\n    "extensions": ["otp"]\n  },\n  "application/vnd.oasis.opendocument.spreadsheet": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ods"]\n  },\n  "application/vnd.oasis.opendocument.spreadsheet-template": {\n    "source": "iana",\n    "extensions": ["ots"]\n  },\n  "application/vnd.oasis.opendocument.text": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["odt"]\n  },\n  "application/vnd.oasis.opendocument.text-master": {\n    "source": "iana",\n    "extensions": ["odm"]\n  },\n  "application/vnd.oasis.opendocument.text-template": {\n    "source": "iana",\n    "extensions": ["ott"]\n  },\n  "application/vnd.oasis.opendocument.text-web": {\n    "source": "iana",\n    "extensions": ["oth"]\n  },\n  "application/vnd.obn": {\n    "source": "iana"\n  },\n  "application/vnd.ocf+cbor": {\n    "source": "iana"\n  },\n  "application/vnd.oci.image.manifest.v1+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oftn.l10n+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.contentaccessdownload+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.contentaccessstreaming+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.cspg-hexbinary": {\n    "source": "iana"\n  },\n  "application/vnd.oipf.dae.svg+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.dae.xhtml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.mippvcontrolmessage+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.pae.gem": {\n    "source": "iana"\n  },\n  "application/vnd.oipf.spdiscovery+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.spdlist+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.ueprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.userprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.olpc-sugar": {\n    "source": "iana",\n    "extensions": ["xo"]\n  },\n  "application/vnd.oma-scws-config": {\n    "source": "iana"\n  },\n  "application/vnd.oma-scws-http-request": {\n    "source": "iana"\n  },\n  "application/vnd.oma-scws-http-response": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.associated-procedure-parameter+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.drm-trigger+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.imd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.ltkm": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.notification+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.provisioningtrigger": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.sgboot": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.sgdd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.sgdu": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.simple-symbol-container": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.smartcard-trigger+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.sprov+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.stkm": {\n    "source": "iana"\n  },\n  "application/vnd.oma.cab-address-book+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-feature-handler+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-pcc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-subs-invite+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-user-prefs+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.dcd": {\n    "source": "iana"\n  },\n  "application/vnd.oma.dcdc": {\n    "source": "iana"\n  },\n  "application/vnd.oma.dd2+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dd2"]\n  },\n  "application/vnd.oma.drm.risd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.group-usage-list+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.lwm2m+cbor": {\n    "source": "iana"\n  },\n  "application/vnd.oma.lwm2m+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.lwm2m+tlv": {\n    "source": "iana"\n  },\n  "application/vnd.oma.pal+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.detailed-progress-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.final-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.groups+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.invocation-descriptor+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.optimized-progress-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.push": {\n    "source": "iana"\n  },\n  "application/vnd.oma.scidm.messages+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.xcap-directory+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.omads-email+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.omads-file+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.omads-folder+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.omaloc-supl-init": {\n    "source": "iana"\n  },\n  "application/vnd.onepager": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertamp": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertamx": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertat": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertatp": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertatx": {\n    "source": "iana"\n  },\n  "application/vnd.openblox.game+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["obgx"]\n  },\n  "application/vnd.openblox.game-binary": {\n    "source": "iana"\n  },\n  "application/vnd.openeye.oeb": {\n    "source": "iana"\n  },\n  "application/vnd.openofficeorg.extension": {\n    "source": "apache",\n    "extensions": ["oxt"]\n  },\n  "application/vnd.openstreetmap.data+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["osm"]\n  },\n  "application/vnd.openxmlformats-officedocument.custom-properties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.customxmlproperties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawing+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.chart+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramdata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.extended-properties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.commentauthors+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.comments+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.notesmaster+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.notesslide+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.presentation": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["pptx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.presprops+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slide": {\n    "source": "iana",\n    "extensions": ["sldx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slide+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slidelayout+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slidemaster+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slideshow": {\n    "source": "iana",\n    "extensions": ["ppsx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.tablestyles+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.tags+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.template": {\n    "source": "iana",\n    "extensions": ["potx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.viewprops+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["xlsx"]\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.template": {\n    "source": "iana",\n    "extensions": ["xltx"]\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.theme+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.themeoverride+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.vmldrawing": {\n    "source": "iana"\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["docx"]\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.template": {\n    "source": "iana",\n    "extensions": ["dotx"]\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-package.core-properties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-package.relationships+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oracle.resource+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.orange.indata": {\n    "source": "iana"\n  },\n  "application/vnd.osa.netdeploy": {\n    "source": "iana"\n  },\n  "application/vnd.osgeo.mapguide.package": {\n    "source": "iana",\n    "extensions": ["mgp"]\n  },\n  "application/vnd.osgi.bundle": {\n    "source": "iana"\n  },\n  "application/vnd.osgi.dp": {\n    "source": "iana",\n    "extensions": ["dp"]\n  },\n  "application/vnd.osgi.subsystem": {\n    "source": "iana",\n    "extensions": ["esa"]\n  },\n  "application/vnd.otps.ct-kip+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oxli.countgraph": {\n    "source": "iana"\n  },\n  "application/vnd.pagerduty+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.palm": {\n    "source": "iana",\n    "extensions": ["pdb","pqa","oprc"]\n  },\n  "application/vnd.panoply": {\n    "source": "iana"\n  },\n  "application/vnd.paos.xml": {\n    "source": "iana"\n  },\n  "application/vnd.patentdive": {\n    "source": "iana"\n  },\n  "application/vnd.patientecommsdoc": {\n    "source": "iana"\n  },\n  "application/vnd.pawaafile": {\n    "source": "iana",\n    "extensions": ["paw"]\n  },\n  "application/vnd.pcos": {\n    "source": "iana"\n  },\n  "application/vnd.pg.format": {\n    "source": "iana",\n    "extensions": ["str"]\n  },\n  "application/vnd.pg.osasli": {\n    "source": "iana",\n    "extensions": ["ei6"]\n  },\n  "application/vnd.piaccess.application-licence": {\n    "source": "iana"\n  },\n  "application/vnd.picsel": {\n    "source": "iana",\n    "extensions": ["efif"]\n  },\n  "application/vnd.pmi.widget": {\n    "source": "iana",\n    "extensions": ["wg"]\n  },\n  "application/vnd.poc.group-advertisement+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.pocketlearn": {\n    "source": "iana",\n    "extensions": ["plf"]\n  },\n  "application/vnd.powerbuilder6": {\n    "source": "iana",\n    "extensions": ["pbd"]\n  },\n  "application/vnd.powerbuilder6-s": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder7": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder7-s": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder75": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder75-s": {\n    "source": "iana"\n  },\n  "application/vnd.preminet": {\n    "source": "iana"\n  },\n  "application/vnd.previewsystems.box": {\n    "source": "iana",\n    "extensions": ["box"]\n  },\n  "application/vnd.proteus.magazine": {\n    "source": "iana",\n    "extensions": ["mgz"]\n  },\n  "application/vnd.psfs": {\n    "source": "iana"\n  },\n  "application/vnd.publishare-delta-tree": {\n    "source": "iana",\n    "extensions": ["qps"]\n  },\n  "application/vnd.pvi.ptid1": {\n    "source": "iana",\n    "extensions": ["ptid"]\n  },\n  "application/vnd.pwg-multiplexed": {\n    "source": "iana"\n  },\n  "application/vnd.pwg-xhtml-print+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.qualcomm.brew-app-res": {\n    "source": "iana"\n  },\n  "application/vnd.quarantainenet": {\n    "source": "iana"\n  },\n  "application/vnd.quark.quarkxpress": {\n    "source": "iana",\n    "extensions": ["qxd","qxt","qwd","qwt","qxl","qxb"]\n  },\n  "application/vnd.quobject-quoxdocument": {\n    "source": "iana"\n  },\n  "application/vnd.radisys.moml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-conf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-conn+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-dialog+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-stream+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-conf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-base+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-fax-detect+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-fax-sendrecv+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-group+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-speech+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-transform+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.rainstor.data": {\n    "source": "iana"\n  },\n  "application/vnd.rapid": {\n    "source": "iana"\n  },\n  "application/vnd.rar": {\n    "source": "iana",\n    "extensions": ["rar"]\n  },\n  "application/vnd.realvnc.bed": {\n    "source": "iana",\n    "extensions": ["bed"]\n  },\n  "application/vnd.recordare.musicxml": {\n    "source": "iana",\n    "extensions": ["mxl"]\n  },\n  "application/vnd.recordare.musicxml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["musicxml"]\n  },\n  "application/vnd.renlearn.rlprint": {\n    "source": "iana"\n  },\n  "application/vnd.restful+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.rig.cryptonote": {\n    "source": "iana",\n    "extensions": ["cryptonote"]\n  },\n  "application/vnd.rim.cod": {\n    "source": "apache",\n    "extensions": ["cod"]\n  },\n  "application/vnd.rn-realmedia": {\n    "source": "apache",\n    "extensions": ["rm"]\n  },\n  "application/vnd.rn-realmedia-vbr": {\n    "source": "apache",\n    "extensions": ["rmvb"]\n  },\n  "application/vnd.route66.link66+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["link66"]\n  },\n  "application/vnd.rs-274x": {\n    "source": "iana"\n  },\n  "application/vnd.ruckus.download": {\n    "source": "iana"\n  },\n  "application/vnd.s3sms": {\n    "source": "iana"\n  },\n  "application/vnd.sailingtracker.track": {\n    "source": "iana",\n    "extensions": ["st"]\n  },\n  "application/vnd.sar": {\n    "source": "iana"\n  },\n  "application/vnd.sbm.cid": {\n    "source": "iana"\n  },\n  "application/vnd.sbm.mid2": {\n    "source": "iana"\n  },\n  "application/vnd.scribus": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.3df": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.csf": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.doc": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.eml": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.mht": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.net": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.ppt": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.tiff": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.xls": {\n    "source": "iana"\n  },\n  "application/vnd.sealedmedia.softseal.html": {\n    "source": "iana"\n  },\n  "application/vnd.sealedmedia.softseal.pdf": {\n    "source": "iana"\n  },\n  "application/vnd.seemail": {\n    "source": "iana",\n    "extensions": ["see"]\n  },\n  "application/vnd.seis+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.sema": {\n    "source": "iana",\n    "extensions": ["sema"]\n  },\n  "application/vnd.semd": {\n    "source": "iana",\n    "extensions": ["semd"]\n  },\n  "application/vnd.semf": {\n    "source": "iana",\n    "extensions": ["semf"]\n  },\n  "application/vnd.shade-save-file": {\n    "source": "iana"\n  },\n  "application/vnd.shana.informed.formdata": {\n    "source": "iana",\n    "extensions": ["ifm"]\n  },\n  "application/vnd.shana.informed.formtemplate": {\n    "source": "iana",\n    "extensions": ["itp"]\n  },\n  "application/vnd.shana.informed.interchange": {\n    "source": "iana",\n    "extensions": ["iif"]\n  },\n  "application/vnd.shana.informed.package": {\n    "source": "iana",\n    "extensions": ["ipk"]\n  },\n  "application/vnd.shootproof+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.shopkick+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.shp": {\n    "source": "iana"\n  },\n  "application/vnd.shx": {\n    "source": "iana"\n  },\n  "application/vnd.sigrok.session": {\n    "source": "iana"\n  },\n  "application/vnd.simtech-mindmapper": {\n    "source": "iana",\n    "extensions": ["twd","twds"]\n  },\n  "application/vnd.siren+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.smaf": {\n    "source": "iana",\n    "extensions": ["mmf"]\n  },\n  "application/vnd.smart.notebook": {\n    "source": "iana"\n  },\n  "application/vnd.smart.teacher": {\n    "source": "iana",\n    "extensions": ["teacher"]\n  },\n  "application/vnd.snesdev-page-table": {\n    "source": "iana"\n  },\n  "application/vnd.software602.filler.form+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["fo"]\n  },\n  "application/vnd.software602.filler.form-xml-zip": {\n    "source": "iana"\n  },\n  "application/vnd.solent.sdkm+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sdkm","sdkd"]\n  },\n  "application/vnd.spotfire.dxp": {\n    "source": "iana",\n    "extensions": ["dxp"]\n  },\n  "application/vnd.spotfire.sfs": {\n    "source": "iana",\n    "extensions": ["sfs"]\n  },\n  "application/vnd.sqlite3": {\n    "source": "iana"\n  },\n  "application/vnd.sss-cod": {\n    "source": "iana"\n  },\n  "application/vnd.sss-dtf": {\n    "source": "iana"\n  },\n  "application/vnd.sss-ntf": {\n    "source": "iana"\n  },\n  "application/vnd.stardivision.calc": {\n    "source": "apache",\n    "extensions": ["sdc"]\n  },\n  "application/vnd.stardivision.draw": {\n    "source": "apache",\n    "extensions": ["sda"]\n  },\n  "application/vnd.stardivision.impress": {\n    "source": "apache",\n    "extensions": ["sdd"]\n  },\n  "application/vnd.stardivision.math": {\n    "source": "apache",\n    "extensions": ["smf"]\n  },\n  "application/vnd.stardivision.writer": {\n    "source": "apache",\n    "extensions": ["sdw","vor"]\n  },\n  "application/vnd.stardivision.writer-global": {\n    "source": "apache",\n    "extensions": ["sgl"]\n  },\n  "application/vnd.stepmania.package": {\n    "source": "iana",\n    "extensions": ["smzip"]\n  },\n  "application/vnd.stepmania.stepchart": {\n    "source": "iana",\n    "extensions": ["sm"]\n  },\n  "application/vnd.street-stream": {\n    "source": "iana"\n  },\n  "application/vnd.sun.wadl+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wadl"]\n  },\n  "application/vnd.sun.xml.calc": {\n    "source": "apache",\n    "extensions": ["sxc"]\n  },\n  "application/vnd.sun.xml.calc.template": {\n    "source": "apache",\n    "extensions": ["stc"]\n  },\n  "application/vnd.sun.xml.draw": {\n    "source": "apache",\n    "extensions": ["sxd"]\n  },\n  "application/vnd.sun.xml.draw.template": {\n    "source": "apache",\n    "extensions": ["std"]\n  },\n  "application/vnd.sun.xml.impress": {\n    "source": "apache",\n    "extensions": ["sxi"]\n  },\n  "application/vnd.sun.xml.impress.template": {\n    "source": "apache",\n    "extensions": ["sti"]\n  },\n  "application/vnd.sun.xml.math": {\n    "source": "apache",\n    "extensions": ["sxm"]\n  },\n  "application/vnd.sun.xml.writer": {\n    "source": "apache",\n    "extensions": ["sxw"]\n  },\n  "application/vnd.sun.xml.writer.global": {\n    "source": "apache",\n    "extensions": ["sxg"]\n  },\n  "application/vnd.sun.xml.writer.template": {\n    "source": "apache",\n    "extensions": ["stw"]\n  },\n  "application/vnd.sus-calendar": {\n    "source": "iana",\n    "extensions": ["sus","susp"]\n  },\n  "application/vnd.svd": {\n    "source": "iana",\n    "extensions": ["svd"]\n  },\n  "application/vnd.swiftview-ics": {\n    "source": "iana"\n  },\n  "application/vnd.sycle+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.symbian.install": {\n    "source": "apache",\n    "extensions": ["sis","sisx"]\n  },\n  "application/vnd.syncml+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["xsm"]\n  },\n  "application/vnd.syncml.dm+wbxml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["bdm"]\n  },\n  "application/vnd.syncml.dm+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["xdm"]\n  },\n  "application/vnd.syncml.dm.notification": {\n    "source": "iana"\n  },\n  "application/vnd.syncml.dmddf+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.syncml.dmddf+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["ddf"]\n  },\n  "application/vnd.syncml.dmtnds+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.syncml.dmtnds+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.syncml.ds.notification": {\n    "source": "iana"\n  },\n  "application/vnd.tableschema+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.tao.intent-module-archive": {\n    "source": "iana",\n    "extensions": ["tao"]\n  },\n  "application/vnd.tcpdump.pcap": {\n    "source": "iana",\n    "extensions": ["pcap","cap","dmp"]\n  },\n  "application/vnd.think-cell.ppttc+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.tmd.mediaflex.api+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.tml": {\n    "source": "iana"\n  },\n  "application/vnd.tmobile-livetv": {\n    "source": "iana",\n    "extensions": ["tmo"]\n  },\n  "application/vnd.tri.onesource": {\n    "source": "iana"\n  },\n  "application/vnd.trid.tpt": {\n    "source": "iana",\n    "extensions": ["tpt"]\n  },\n  "application/vnd.triscape.mxs": {\n    "source": "iana",\n    "extensions": ["mxs"]\n  },\n  "application/vnd.trueapp": {\n    "source": "iana",\n    "extensions": ["tra"]\n  },\n  "application/vnd.truedoc": {\n    "source": "iana"\n  },\n  "application/vnd.ubisoft.webplayer": {\n    "source": "iana"\n  },\n  "application/vnd.ufdl": {\n    "source": "iana",\n    "extensions": ["ufd","ufdl"]\n  },\n  "application/vnd.uiq.theme": {\n    "source": "iana",\n    "extensions": ["utz"]\n  },\n  "application/vnd.umajin": {\n    "source": "iana",\n    "extensions": ["umj"]\n  },\n  "application/vnd.unity": {\n    "source": "iana",\n    "extensions": ["unityweb"]\n  },\n  "application/vnd.uoml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["uoml"]\n  },\n  "application/vnd.uplanet.alert": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.alert-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.bearer-choice": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.bearer-choice-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.cacheop": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.cacheop-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.channel": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.channel-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.list": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.list-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.listcmd": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.listcmd-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.signal": {\n    "source": "iana"\n  },\n  "application/vnd.uri-map": {\n    "source": "iana"\n  },\n  "application/vnd.valve.source.material": {\n    "source": "iana"\n  },\n  "application/vnd.vcx": {\n    "source": "iana",\n    "extensions": ["vcx"]\n  },\n  "application/vnd.vd-study": {\n    "source": "iana"\n  },\n  "application/vnd.vectorworks": {\n    "source": "iana"\n  },\n  "application/vnd.vel+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.verimatrix.vcas": {\n    "source": "iana"\n  },\n  "application/vnd.veryant.thin": {\n    "source": "iana"\n  },\n  "application/vnd.ves.encrypted": {\n    "source": "iana"\n  },\n  "application/vnd.vidsoft.vidconference": {\n    "source": "iana"\n  },\n  "application/vnd.visio": {\n    "source": "iana",\n    "extensions": ["vsd","vst","vss","vsw"]\n  },\n  "application/vnd.visionary": {\n    "source": "iana",\n    "extensions": ["vis"]\n  },\n  "application/vnd.vividence.scriptfile": {\n    "source": "iana"\n  },\n  "application/vnd.vsf": {\n    "source": "iana",\n    "extensions": ["vsf"]\n  },\n  "application/vnd.wap.sic": {\n    "source": "iana"\n  },\n  "application/vnd.wap.slc": {\n    "source": "iana"\n  },\n  "application/vnd.wap.wbxml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["wbxml"]\n  },\n  "application/vnd.wap.wmlc": {\n    "source": "iana",\n    "extensions": ["wmlc"]\n  },\n  "application/vnd.wap.wmlscriptc": {\n    "source": "iana",\n    "extensions": ["wmlsc"]\n  },\n  "application/vnd.webturbo": {\n    "source": "iana",\n    "extensions": ["wtb"]\n  },\n  "application/vnd.wfa.dpp": {\n    "source": "iana"\n  },\n  "application/vnd.wfa.p2p": {\n    "source": "iana"\n  },\n  "application/vnd.wfa.wsc": {\n    "source": "iana"\n  },\n  "application/vnd.windows.devicepairing": {\n    "source": "iana"\n  },\n  "application/vnd.wmc": {\n    "source": "iana"\n  },\n  "application/vnd.wmf.bootstrap": {\n    "source": "iana"\n  },\n  "application/vnd.wolfram.mathematica": {\n    "source": "iana"\n  },\n  "application/vnd.wolfram.mathematica.package": {\n    "source": "iana"\n  },\n  "application/vnd.wolfram.player": {\n    "source": "iana",\n    "extensions": ["nbp"]\n  },\n  "application/vnd.wordperfect": {\n    "source": "iana",\n    "extensions": ["wpd"]\n  },\n  "application/vnd.wqd": {\n    "source": "iana",\n    "extensions": ["wqd"]\n  },\n  "application/vnd.wrq-hp3000-labelled": {\n    "source": "iana"\n  },\n  "application/vnd.wt.stf": {\n    "source": "iana",\n    "extensions": ["stf"]\n  },\n  "application/vnd.wv.csp+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.wv.csp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.wv.ssp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.xacml+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.xara": {\n    "source": "iana",\n    "extensions": ["xar"]\n  },\n  "application/vnd.xfdl": {\n    "source": "iana",\n    "extensions": ["xfdl"]\n  },\n  "application/vnd.xfdl.webform": {\n    "source": "iana"\n  },\n  "application/vnd.xmi+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.xmpie.cpkg": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.dpkg": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.plan": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.ppkg": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.xlim": {\n    "source": "iana"\n  },\n  "application/vnd.yamaha.hv-dic": {\n    "source": "iana",\n    "extensions": ["hvd"]\n  },\n  "application/vnd.yamaha.hv-script": {\n    "source": "iana",\n    "extensions": ["hvs"]\n  },\n  "application/vnd.yamaha.hv-voice": {\n    "source": "iana",\n    "extensions": ["hvp"]\n  },\n  "application/vnd.yamaha.openscoreformat": {\n    "source": "iana",\n    "extensions": ["osf"]\n  },\n  "application/vnd.yamaha.openscoreformat.osfpvg+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["osfpvg"]\n  },\n  "application/vnd.yamaha.remote-setup": {\n    "source": "iana"\n  },\n  "application/vnd.yamaha.smaf-audio": {\n    "source": "iana",\n    "extensions": ["saf"]\n  },\n  "application/vnd.yamaha.smaf-phrase": {\n    "source": "iana",\n    "extensions": ["spf"]\n  },\n  "application/vnd.yamaha.through-ngn": {\n    "source": "iana"\n  },\n  "application/vnd.yamaha.tunnel-udpencap": {\n    "source": "iana"\n  },\n  "application/vnd.yaoweme": {\n    "source": "iana"\n  },\n  "application/vnd.yellowriver-custom-menu": {\n    "source": "iana",\n    "extensions": ["cmp"]\n  },\n  "application/vnd.youtube.yt": {\n    "source": "iana"\n  },\n  "application/vnd.zul": {\n    "source": "iana",\n    "extensions": ["zir","zirz"]\n  },\n  "application/vnd.zzazz.deck+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["zaz"]\n  },\n  "application/voicexml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["vxml"]\n  },\n  "application/voucher-cms+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vq-rtcpxr": {\n    "source": "iana"\n  },\n  "application/wasm": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wasm"]\n  },\n  "application/watcherinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/webpush-options+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/whoispp-query": {\n    "source": "iana"\n  },\n  "application/whoispp-response": {\n    "source": "iana"\n  },\n  "application/widget": {\n    "source": "iana",\n    "extensions": ["wgt"]\n  },\n  "application/winhlp": {\n    "source": "apache",\n    "extensions": ["hlp"]\n  },\n  "application/wita": {\n    "source": "iana"\n  },\n  "application/wordperfect5.1": {\n    "source": "iana"\n  },\n  "application/wsdl+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wsdl"]\n  },\n  "application/wspolicy+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wspolicy"]\n  },\n  "application/x-7z-compressed": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["7z"]\n  },\n  "application/x-abiword": {\n    "source": "apache",\n    "extensions": ["abw"]\n  },\n  "application/x-ace-compressed": {\n    "source": "apache",\n    "extensions": ["ace"]\n  },\n  "application/x-amf": {\n    "source": "apache"\n  },\n  "application/x-apple-diskimage": {\n    "source": "apache",\n    "extensions": ["dmg"]\n  },\n  "application/x-arj": {\n    "compressible": false,\n    "extensions": ["arj"]\n  },\n  "application/x-authorware-bin": {\n    "source": "apache",\n    "extensions": ["aab","x32","u32","vox"]\n  },\n  "application/x-authorware-map": {\n    "source": "apache",\n    "extensions": ["aam"]\n  },\n  "application/x-authorware-seg": {\n    "source": "apache",\n    "extensions": ["aas"]\n  },\n  "application/x-bcpio": {\n    "source": "apache",\n    "extensions": ["bcpio"]\n  },\n  "application/x-bdoc": {\n    "compressible": false,\n    "extensions": ["bdoc"]\n  },\n  "application/x-bittorrent": {\n    "source": "apache",\n    "extensions": ["torrent"]\n  },\n  "application/x-blorb": {\n    "source": "apache",\n    "extensions": ["blb","blorb"]\n  },\n  "application/x-bzip": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["bz"]\n  },\n  "application/x-bzip2": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["bz2","boz"]\n  },\n  "application/x-cbr": {\n    "source": "apache",\n    "extensions": ["cbr","cba","cbt","cbz","cb7"]\n  },\n  "application/x-cdlink": {\n    "source": "apache",\n    "extensions": ["vcd"]\n  },\n  "application/x-cfs-compressed": {\n    "source": "apache",\n    "extensions": ["cfs"]\n  },\n  "application/x-chat": {\n    "source": "apache",\n    "extensions": ["chat"]\n  },\n  "application/x-chess-pgn": {\n    "source": "apache",\n    "extensions": ["pgn"]\n  },\n  "application/x-chrome-extension": {\n    "extensions": ["crx"]\n  },\n  "application/x-cocoa": {\n    "source": "nginx",\n    "extensions": ["cco"]\n  },\n  "application/x-compress": {\n    "source": "apache"\n  },\n  "application/x-conference": {\n    "source": "apache",\n    "extensions": ["nsc"]\n  },\n  "application/x-cpio": {\n    "source": "apache",\n    "extensions": ["cpio"]\n  },\n  "application/x-csh": {\n    "source": "apache",\n    "extensions": ["csh"]\n  },\n  "application/x-deb": {\n    "compressible": false\n  },\n  "application/x-debian-package": {\n    "source": "apache",\n    "extensions": ["deb","udeb"]\n  },\n  "application/x-dgc-compressed": {\n    "source": "apache",\n    "extensions": ["dgc"]\n  },\n  "application/x-director": {\n    "source": "apache",\n    "extensions": ["dir","dcr","dxr","cst","cct","cxt","w3d","fgd","swa"]\n  },\n  "application/x-doom": {\n    "source": "apache",\n    "extensions": ["wad"]\n  },\n  "application/x-dtbncx+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["ncx"]\n  },\n  "application/x-dtbook+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["dtb"]\n  },\n  "application/x-dtbresource+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["res"]\n  },\n  "application/x-dvi": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["dvi"]\n  },\n  "application/x-envoy": {\n    "source": "apache",\n    "extensions": ["evy"]\n  },\n  "application/x-eva": {\n    "source": "apache",\n    "extensions": ["eva"]\n  },\n  "application/x-font-bdf": {\n    "source": "apache",\n    "extensions": ["bdf"]\n  },\n  "application/x-font-dos": {\n    "source": "apache"\n  },\n  "application/x-font-framemaker": {\n    "source": "apache"\n  },\n  "application/x-font-ghostscript": {\n    "source": "apache",\n    "extensions": ["gsf"]\n  },\n  "application/x-font-libgrx": {\n    "source": "apache"\n  },\n  "application/x-font-linux-psf": {\n    "source": "apache",\n    "extensions": ["psf"]\n  },\n  "application/x-font-pcf": {\n    "source": "apache",\n    "extensions": ["pcf"]\n  },\n  "application/x-font-snf": {\n    "source": "apache",\n    "extensions": ["snf"]\n  },\n  "application/x-font-speedo": {\n    "source": "apache"\n  },\n  "application/x-font-sunos-news": {\n    "source": "apache"\n  },\n  "application/x-font-type1": {\n    "source": "apache",\n    "extensions": ["pfa","pfb","pfm","afm"]\n  },\n  "application/x-font-vfont": {\n    "source": "apache"\n  },\n  "application/x-freearc": {\n    "source": "apache",\n    "extensions": ["arc"]\n  },\n  "application/x-futuresplash": {\n    "source": "apache",\n    "extensions": ["spl"]\n  },\n  "application/x-gca-compressed": {\n    "source": "apache",\n    "extensions": ["gca"]\n  },\n  "application/x-glulx": {\n    "source": "apache",\n    "extensions": ["ulx"]\n  },\n  "application/x-gnumeric": {\n    "source": "apache",\n    "extensions": ["gnumeric"]\n  },\n  "application/x-gramps-xml": {\n    "source": "apache",\n    "extensions": ["gramps"]\n  },\n  "application/x-gtar": {\n    "source": "apache",\n    "extensions": ["gtar"]\n  },\n  "application/x-gzip": {\n    "source": "apache"\n  },\n  "application/x-hdf": {\n    "source": "apache",\n    "extensions": ["hdf"]\n  },\n  "application/x-httpd-php": {\n    "compressible": true,\n    "extensions": ["php"]\n  },\n  "application/x-install-instructions": {\n    "source": "apache",\n    "extensions": ["install"]\n  },\n  "application/x-iso9660-image": {\n    "source": "apache",\n    "extensions": ["iso"]\n  },\n  "application/x-java-archive-diff": {\n    "source": "nginx",\n    "extensions": ["jardiff"]\n  },\n  "application/x-java-jnlp-file": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["jnlp"]\n  },\n  "application/x-javascript": {\n    "compressible": true\n  },\n  "application/x-keepass2": {\n    "extensions": ["kdbx"]\n  },\n  "application/x-latex": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["latex"]\n  },\n  "application/x-lua-bytecode": {\n    "extensions": ["luac"]\n  },\n  "application/x-lzh-compressed": {\n    "source": "apache",\n    "extensions": ["lzh","lha"]\n  },\n  "application/x-makeself": {\n    "source": "nginx",\n    "extensions": ["run"]\n  },\n  "application/x-mie": {\n    "source": "apache",\n    "extensions": ["mie"]\n  },\n  "application/x-mobipocket-ebook": {\n    "source": "apache",\n    "extensions": ["prc","mobi"]\n  },\n  "application/x-mpegurl": {\n    "compressible": false\n  },\n  "application/x-ms-application": {\n    "source": "apache",\n    "extensions": ["application"]\n  },\n  "application/x-ms-shortcut": {\n    "source": "apache",\n    "extensions": ["lnk"]\n  },\n  "application/x-ms-wmd": {\n    "source": "apache",\n    "extensions": ["wmd"]\n  },\n  "application/x-ms-wmz": {\n    "source": "apache",\n    "extensions": ["wmz"]\n  },\n  "application/x-ms-xbap": {\n    "source": "apache",\n    "extensions": ["xbap"]\n  },\n  "application/x-msaccess": {\n    "source": "apache",\n    "extensions": ["mdb"]\n  },\n  "application/x-msbinder": {\n    "source": "apache",\n    "extensions": ["obd"]\n  },\n  "application/x-mscardfile": {\n    "source": "apache",\n    "extensions": ["crd"]\n  },\n  "application/x-msclip": {\n    "source": "apache",\n    "extensions": ["clp"]\n  },\n  "application/x-msdos-program": {\n    "extensions": ["exe"]\n  },\n  "application/x-msdownload": {\n    "source": "apache",\n    "extensions": ["exe","dll","com","bat","msi"]\n  },\n  "application/x-msmediaview": {\n    "source": "apache",\n    "extensions": ["mvb","m13","m14"]\n  },\n  "application/x-msmetafile": {\n    "source": "apache",\n    "extensions": ["wmf","wmz","emf","emz"]\n  },\n  "application/x-msmoney": {\n    "source": "apache",\n    "extensions": ["mny"]\n  },\n  "application/x-mspublisher": {\n    "source": "apache",\n    "extensions": ["pub"]\n  },\n  "application/x-msschedule": {\n    "source": "apache",\n    "extensions": ["scd"]\n  },\n  "application/x-msterminal": {\n    "source": "apache",\n    "extensions": ["trm"]\n  },\n  "application/x-mswrite": {\n    "source": "apache",\n    "extensions": ["wri"]\n  },\n  "application/x-netcdf": {\n    "source": "apache",\n    "extensions": ["nc","cdf"]\n  },\n  "application/x-ns-proxy-autoconfig": {\n    "compressible": true,\n    "extensions": ["pac"]\n  },\n  "application/x-nzb": {\n    "source": "apache",\n    "extensions": ["nzb"]\n  },\n  "application/x-perl": {\n    "source": "nginx",\n    "extensions": ["pl","pm"]\n  },\n  "application/x-pilot": {\n    "source": "nginx",\n    "extensions": ["prc","pdb"]\n  },\n  "application/x-pkcs12": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["p12","pfx"]\n  },\n  "application/x-pkcs7-certificates": {\n    "source": "apache",\n    "extensions": ["p7b","spc"]\n  },\n  "application/x-pkcs7-certreqresp": {\n    "source": "apache",\n    "extensions": ["p7r"]\n  },\n  "application/x-pki-message": {\n    "source": "iana"\n  },\n  "application/x-rar-compressed": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["rar"]\n  },\n  "application/x-redhat-package-manager": {\n    "source": "nginx",\n    "extensions": ["rpm"]\n  },\n  "application/x-research-info-systems": {\n    "source": "apache",\n    "extensions": ["ris"]\n  },\n  "application/x-sea": {\n    "source": "nginx",\n    "extensions": ["sea"]\n  },\n  "application/x-sh": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["sh"]\n  },\n  "application/x-shar": {\n    "source": "apache",\n    "extensions": ["shar"]\n  },\n  "application/x-shockwave-flash": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["swf"]\n  },\n  "application/x-silverlight-app": {\n    "source": "apache",\n    "extensions": ["xap"]\n  },\n  "application/x-sql": {\n    "source": "apache",\n    "extensions": ["sql"]\n  },\n  "application/x-stuffit": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["sit"]\n  },\n  "application/x-stuffitx": {\n    "source": "apache",\n    "extensions": ["sitx"]\n  },\n  "application/x-subrip": {\n    "source": "apache",\n    "extensions": ["srt"]\n  },\n  "application/x-sv4cpio": {\n    "source": "apache",\n    "extensions": ["sv4cpio"]\n  },\n  "application/x-sv4crc": {\n    "source": "apache",\n    "extensions": ["sv4crc"]\n  },\n  "application/x-t3vm-image": {\n    "source": "apache",\n    "extensions": ["t3"]\n  },\n  "application/x-tads": {\n    "source": "apache",\n    "extensions": ["gam"]\n  },\n  "application/x-tar": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["tar"]\n  },\n  "application/x-tcl": {\n    "source": "apache",\n    "extensions": ["tcl","tk"]\n  },\n  "application/x-tex": {\n    "source": "apache",\n    "extensions": ["tex"]\n  },\n  "application/x-tex-tfm": {\n    "source": "apache",\n    "extensions": ["tfm"]\n  },\n  "application/x-texinfo": {\n    "source": "apache",\n    "extensions": ["texinfo","texi"]\n  },\n  "application/x-tgif": {\n    "source": "apache",\n    "extensions": ["obj"]\n  },\n  "application/x-ustar": {\n    "source": "apache",\n    "extensions": ["ustar"]\n  },\n  "application/x-virtualbox-hdd": {\n    "compressible": true,\n    "extensions": ["hdd"]\n  },\n  "application/x-virtualbox-ova": {\n    "compressible": true,\n    "extensions": ["ova"]\n  },\n  "application/x-virtualbox-ovf": {\n    "compressible": true,\n    "extensions": ["ovf"]\n  },\n  "application/x-virtualbox-vbox": {\n    "compressible": true,\n    "extensions": ["vbox"]\n  },\n  "application/x-virtualbox-vbox-extpack": {\n    "compressible": false,\n    "extensions": ["vbox-extpack"]\n  },\n  "application/x-virtualbox-vdi": {\n    "compressible": true,\n    "extensions": ["vdi"]\n  },\n  "application/x-virtualbox-vhd": {\n    "compressible": true,\n    "extensions": ["vhd"]\n  },\n  "application/x-virtualbox-vmdk": {\n    "compressible": true,\n    "extensions": ["vmdk"]\n  },\n  "application/x-wais-source": {\n    "source": "apache",\n    "extensions": ["src"]\n  },\n  "application/x-web-app-manifest+json": {\n    "compressible": true,\n    "extensions": ["webapp"]\n  },\n  "application/x-www-form-urlencoded": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/x-x509-ca-cert": {\n    "source": "iana",\n    "extensions": ["der","crt","pem"]\n  },\n  "application/x-x509-ca-ra-cert": {\n    "source": "iana"\n  },\n  "application/x-x509-next-ca-cert": {\n    "source": "iana"\n  },\n  "application/x-xfig": {\n    "source": "apache",\n    "extensions": ["fig"]\n  },\n  "application/x-xliff+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xlf"]\n  },\n  "application/x-xpinstall": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["xpi"]\n  },\n  "application/x-xz": {\n    "source": "apache",\n    "extensions": ["xz"]\n  },\n  "application/x-zmachine": {\n    "source": "apache",\n    "extensions": ["z1","z2","z3","z4","z5","z6","z7","z8"]\n  },\n  "application/x400-bp": {\n    "source": "iana"\n  },\n  "application/xacml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xaml+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xaml"]\n  },\n  "application/xcap-att+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xav"]\n  },\n  "application/xcap-caps+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xca"]\n  },\n  "application/xcap-diff+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdf"]\n  },\n  "application/xcap-el+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xel"]\n  },\n  "application/xcap-error+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xcap-ns+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xns"]\n  },\n  "application/xcon-conference-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xcon-conference-info-diff+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xenc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xenc"]\n  },\n  "application/xhtml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xhtml","xht"]\n  },\n  "application/xhtml-voice+xml": {\n    "source": "apache",\n    "compressible": true\n  },\n  "application/xliff+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xlf"]\n  },\n  "application/xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xml","xsl","xsd","rng"]\n  },\n  "application/xml-dtd": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dtd"]\n  },\n  "application/xml-external-parsed-entity": {\n    "source": "iana"\n  },\n  "application/xml-patch+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xmpp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xop+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xop"]\n  },\n  "application/xproc+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xpl"]\n  },\n  "application/xslt+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xsl","xslt"]\n  },\n  "application/xspf+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xspf"]\n  },\n  "application/xv+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mxml","xhvml","xvml","xvm"]\n  },\n  "application/yang": {\n    "source": "iana",\n    "extensions": ["yang"]\n  },\n  "application/yang-data+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yang-data+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yang-patch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yang-patch+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yin+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["yin"]\n  },\n  "application/zip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["zip"]\n  },\n  "application/zlib": {\n    "source": "iana"\n  },\n  "application/zstd": {\n    "source": "iana"\n  },\n  "audio/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "audio/32kadpcm": {\n    "source": "iana"\n  },\n  "audio/3gpp": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["3gpp"]\n  },\n  "audio/3gpp2": {\n    "source": "iana"\n  },\n  "audio/aac": {\n    "source": "iana"\n  },\n  "audio/ac3": {\n    "source": "iana"\n  },\n  "audio/adpcm": {\n    "source": "apache",\n    "extensions": ["adp"]\n  },\n  "audio/amr": {\n    "source": "iana",\n    "extensions": ["amr"]\n  },\n  "audio/amr-wb": {\n    "source": "iana"\n  },\n  "audio/amr-wb+": {\n    "source": "iana"\n  },\n  "audio/aptx": {\n    "source": "iana"\n  },\n  "audio/asc": {\n    "source": "iana"\n  },\n  "audio/atrac-advanced-lossless": {\n    "source": "iana"\n  },\n  "audio/atrac-x": {\n    "source": "iana"\n  },\n  "audio/atrac3": {\n    "source": "iana"\n  },\n  "audio/basic": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["au","snd"]\n  },\n  "audio/bv16": {\n    "source": "iana"\n  },\n  "audio/bv32": {\n    "source": "iana"\n  },\n  "audio/clearmode": {\n    "source": "iana"\n  },\n  "audio/cn": {\n    "source": "iana"\n  },\n  "audio/dat12": {\n    "source": "iana"\n  },\n  "audio/dls": {\n    "source": "iana"\n  },\n  "audio/dsr-es201108": {\n    "source": "iana"\n  },\n  "audio/dsr-es202050": {\n    "source": "iana"\n  },\n  "audio/dsr-es202211": {\n    "source": "iana"\n  },\n  "audio/dsr-es202212": {\n    "source": "iana"\n  },\n  "audio/dv": {\n    "source": "iana"\n  },\n  "audio/dvi4": {\n    "source": "iana"\n  },\n  "audio/eac3": {\n    "source": "iana"\n  },\n  "audio/encaprtp": {\n    "source": "iana"\n  },\n  "audio/evrc": {\n    "source": "iana"\n  },\n  "audio/evrc-qcp": {\n    "source": "iana"\n  },\n  "audio/evrc0": {\n    "source": "iana"\n  },\n  "audio/evrc1": {\n    "source": "iana"\n  },\n  "audio/evrcb": {\n    "source": "iana"\n  },\n  "audio/evrcb0": {\n    "source": "iana"\n  },\n  "audio/evrcb1": {\n    "source": "iana"\n  },\n  "audio/evrcnw": {\n    "source": "iana"\n  },\n  "audio/evrcnw0": {\n    "source": "iana"\n  },\n  "audio/evrcnw1": {\n    "source": "iana"\n  },\n  "audio/evrcwb": {\n    "source": "iana"\n  },\n  "audio/evrcwb0": {\n    "source": "iana"\n  },\n  "audio/evrcwb1": {\n    "source": "iana"\n  },\n  "audio/evs": {\n    "source": "iana"\n  },\n  "audio/flexfec": {\n    "source": "iana"\n  },\n  "audio/fwdred": {\n    "source": "iana"\n  },\n  "audio/g711-0": {\n    "source": "iana"\n  },\n  "audio/g719": {\n    "source": "iana"\n  },\n  "audio/g722": {\n    "source": "iana"\n  },\n  "audio/g7221": {\n    "source": "iana"\n  },\n  "audio/g723": {\n    "source": "iana"\n  },\n  "audio/g726-16": {\n    "source": "iana"\n  },\n  "audio/g726-24": {\n    "source": "iana"\n  },\n  "audio/g726-32": {\n    "source": "iana"\n  },\n  "audio/g726-40": {\n    "source": "iana"\n  },\n  "audio/g728": {\n    "source": "iana"\n  },\n  "audio/g729": {\n    "source": "iana"\n  },\n  "audio/g7291": {\n    "source": "iana"\n  },\n  "audio/g729d": {\n    "source": "iana"\n  },\n  "audio/g729e": {\n    "source": "iana"\n  },\n  "audio/gsm": {\n    "source": "iana"\n  },\n  "audio/gsm-efr": {\n    "source": "iana"\n  },\n  "audio/gsm-hr-08": {\n    "source": "iana"\n  },\n  "audio/ilbc": {\n    "source": "iana"\n  },\n  "audio/ip-mr_v2.5": {\n    "source": "iana"\n  },\n  "audio/isac": {\n    "source": "apache"\n  },\n  "audio/l16": {\n    "source": "iana"\n  },\n  "audio/l20": {\n    "source": "iana"\n  },\n  "audio/l24": {\n    "source": "iana",\n    "compressible": false\n  },\n  "audio/l8": {\n    "source": "iana"\n  },\n  "audio/lpc": {\n    "source": "iana"\n  },\n  "audio/melp": {\n    "source": "iana"\n  },\n  "audio/melp1200": {\n    "source": "iana"\n  },\n  "audio/melp2400": {\n    "source": "iana"\n  },\n  "audio/melp600": {\n    "source": "iana"\n  },\n  "audio/mhas": {\n    "source": "iana"\n  },\n  "audio/midi": {\n    "source": "apache",\n    "extensions": ["mid","midi","kar","rmi"]\n  },\n  "audio/mobile-xmf": {\n    "source": "iana",\n    "extensions": ["mxmf"]\n  },\n  "audio/mp3": {\n    "compressible": false,\n    "extensions": ["mp3"]\n  },\n  "audio/mp4": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["m4a","mp4a"]\n  },\n  "audio/mp4a-latm": {\n    "source": "iana"\n  },\n  "audio/mpa": {\n    "source": "iana"\n  },\n  "audio/mpa-robust": {\n    "source": "iana"\n  },\n  "audio/mpeg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["mpga","mp2","mp2a","mp3","m2a","m3a"]\n  },\n  "audio/mpeg4-generic": {\n    "source": "iana"\n  },\n  "audio/musepack": {\n    "source": "apache"\n  },\n  "audio/ogg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["oga","ogg","spx","opus"]\n  },\n  "audio/opus": {\n    "source": "iana"\n  },\n  "audio/parityfec": {\n    "source": "iana"\n  },\n  "audio/pcma": {\n    "source": "iana"\n  },\n  "audio/pcma-wb": {\n    "source": "iana"\n  },\n  "audio/pcmu": {\n    "source": "iana"\n  },\n  "audio/pcmu-wb": {\n    "source": "iana"\n  },\n  "audio/prs.sid": {\n    "source": "iana"\n  },\n  "audio/qcelp": {\n    "source": "iana"\n  },\n  "audio/raptorfec": {\n    "source": "iana"\n  },\n  "audio/red": {\n    "source": "iana"\n  },\n  "audio/rtp-enc-aescm128": {\n    "source": "iana"\n  },\n  "audio/rtp-midi": {\n    "source": "iana"\n  },\n  "audio/rtploopback": {\n    "source": "iana"\n  },\n  "audio/rtx": {\n    "source": "iana"\n  },\n  "audio/s3m": {\n    "source": "apache",\n    "extensions": ["s3m"]\n  },\n  "audio/scip": {\n    "source": "iana"\n  },\n  "audio/silk": {\n    "source": "apache",\n    "extensions": ["sil"]\n  },\n  "audio/smv": {\n    "source": "iana"\n  },\n  "audio/smv-qcp": {\n    "source": "iana"\n  },\n  "audio/smv0": {\n    "source": "iana"\n  },\n  "audio/sofa": {\n    "source": "iana"\n  },\n  "audio/sp-midi": {\n    "source": "iana"\n  },\n  "audio/speex": {\n    "source": "iana"\n  },\n  "audio/t140c": {\n    "source": "iana"\n  },\n  "audio/t38": {\n    "source": "iana"\n  },\n  "audio/telephone-event": {\n    "source": "iana"\n  },\n  "audio/tetra_acelp": {\n    "source": "iana"\n  },\n  "audio/tetra_acelp_bb": {\n    "source": "iana"\n  },\n  "audio/tone": {\n    "source": "iana"\n  },\n  "audio/tsvcis": {\n    "source": "iana"\n  },\n  "audio/uemclip": {\n    "source": "iana"\n  },\n  "audio/ulpfec": {\n    "source": "iana"\n  },\n  "audio/usac": {\n    "source": "iana"\n  },\n  "audio/vdvi": {\n    "source": "iana"\n  },\n  "audio/vmr-wb": {\n    "source": "iana"\n  },\n  "audio/vnd.3gpp.iufp": {\n    "source": "iana"\n  },\n  "audio/vnd.4sb": {\n    "source": "iana"\n  },\n  "audio/vnd.audiokoz": {\n    "source": "iana"\n  },\n  "audio/vnd.celp": {\n    "source": "iana"\n  },\n  "audio/vnd.cisco.nse": {\n    "source": "iana"\n  },\n  "audio/vnd.cmles.radio-events": {\n    "source": "iana"\n  },\n  "audio/vnd.cns.anp1": {\n    "source": "iana"\n  },\n  "audio/vnd.cns.inf1": {\n    "source": "iana"\n  },\n  "audio/vnd.dece.audio": {\n    "source": "iana",\n    "extensions": ["uva","uvva"]\n  },\n  "audio/vnd.digital-winds": {\n    "source": "iana",\n    "extensions": ["eol"]\n  },\n  "audio/vnd.dlna.adts": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.heaac.1": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.heaac.2": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.mlp": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.mps": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pl2": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pl2x": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pl2z": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pulse.1": {\n    "source": "iana"\n  },\n  "audio/vnd.dra": {\n    "source": "iana",\n    "extensions": ["dra"]\n  },\n  "audio/vnd.dts": {\n    "source": "iana",\n    "extensions": ["dts"]\n  },\n  "audio/vnd.dts.hd": {\n    "source": "iana",\n    "extensions": ["dtshd"]\n  },\n  "audio/vnd.dts.uhd": {\n    "source": "iana"\n  },\n  "audio/vnd.dvb.file": {\n    "source": "iana"\n  },\n  "audio/vnd.everad.plj": {\n    "source": "iana"\n  },\n  "audio/vnd.hns.audio": {\n    "source": "iana"\n  },\n  "audio/vnd.lucent.voice": {\n    "source": "iana",\n    "extensions": ["lvp"]\n  },\n  "audio/vnd.ms-playready.media.pya": {\n    "source": "iana",\n    "extensions": ["pya"]\n  },\n  "audio/vnd.nokia.mobile-xmf": {\n    "source": "iana"\n  },\n  "audio/vnd.nortel.vbk": {\n    "source": "iana"\n  },\n  "audio/vnd.nuera.ecelp4800": {\n    "source": "iana",\n    "extensions": ["ecelp4800"]\n  },\n  "audio/vnd.nuera.ecelp7470": {\n    "source": "iana",\n    "extensions": ["ecelp7470"]\n  },\n  "audio/vnd.nuera.ecelp9600": {\n    "source": "iana",\n    "extensions": ["ecelp9600"]\n  },\n  "audio/vnd.octel.sbc": {\n    "source": "iana"\n  },\n  "audio/vnd.presonus.multitrack": {\n    "source": "iana"\n  },\n  "audio/vnd.qcelp": {\n    "source": "iana"\n  },\n  "audio/vnd.rhetorex.32kadpcm": {\n    "source": "iana"\n  },\n  "audio/vnd.rip": {\n    "source": "iana",\n    "extensions": ["rip"]\n  },\n  "audio/vnd.rn-realaudio": {\n    "compressible": false\n  },\n  "audio/vnd.sealedmedia.softseal.mpeg": {\n    "source": "iana"\n  },\n  "audio/vnd.vmx.cvsd": {\n    "source": "iana"\n  },\n  "audio/vnd.wave": {\n    "compressible": false\n  },\n  "audio/vorbis": {\n    "source": "iana",\n    "compressible": false\n  },\n  "audio/vorbis-config": {\n    "source": "iana"\n  },\n  "audio/wav": {\n    "compressible": false,\n    "extensions": ["wav"]\n  },\n  "audio/wave": {\n    "compressible": false,\n    "extensions": ["wav"]\n  },\n  "audio/webm": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["weba"]\n  },\n  "audio/x-aac": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["aac"]\n  },\n  "audio/x-aiff": {\n    "source": "apache",\n    "extensions": ["aif","aiff","aifc"]\n  },\n  "audio/x-caf": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["caf"]\n  },\n  "audio/x-flac": {\n    "source": "apache",\n    "extensions": ["flac"]\n  },\n  "audio/x-m4a": {\n    "source": "nginx",\n    "extensions": ["m4a"]\n  },\n  "audio/x-matroska": {\n    "source": "apache",\n    "extensions": ["mka"]\n  },\n  "audio/x-mpegurl": {\n    "source": "apache",\n    "extensions": ["m3u"]\n  },\n  "audio/x-ms-wax": {\n    "source": "apache",\n    "extensions": ["wax"]\n  },\n  "audio/x-ms-wma": {\n    "source": "apache",\n    "extensions": ["wma"]\n  },\n  "audio/x-pn-realaudio": {\n    "source": "apache",\n    "extensions": ["ram","ra"]\n  },\n  "audio/x-pn-realaudio-plugin": {\n    "source": "apache",\n    "extensions": ["rmp"]\n  },\n  "audio/x-realaudio": {\n    "source": "nginx",\n    "extensions": ["ra"]\n  },\n  "audio/x-tta": {\n    "source": "apache"\n  },\n  "audio/x-wav": {\n    "source": "apache",\n    "extensions": ["wav"]\n  },\n  "audio/xm": {\n    "source": "apache",\n    "extensions": ["xm"]\n  },\n  "chemical/x-cdx": {\n    "source": "apache",\n    "extensions": ["cdx"]\n  },\n  "chemical/x-cif": {\n    "source": "apache",\n    "extensions": ["cif"]\n  },\n  "chemical/x-cmdf": {\n    "source": "apache",\n    "extensions": ["cmdf"]\n  },\n  "chemical/x-cml": {\n    "source": "apache",\n    "extensions": ["cml"]\n  },\n  "chemical/x-csml": {\n    "source": "apache",\n    "extensions": ["csml"]\n  },\n  "chemical/x-pdb": {\n    "source": "apache"\n  },\n  "chemical/x-xyz": {\n    "source": "apache",\n    "extensions": ["xyz"]\n  },\n  "font/collection": {\n    "source": "iana",\n    "extensions": ["ttc"]\n  },\n  "font/otf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["otf"]\n  },\n  "font/sfnt": {\n    "source": "iana"\n  },\n  "font/ttf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ttf"]\n  },\n  "font/woff": {\n    "source": "iana",\n    "extensions": ["woff"]\n  },\n  "font/woff2": {\n    "source": "iana",\n    "extensions": ["woff2"]\n  },\n  "image/aces": {\n    "source": "iana",\n    "extensions": ["exr"]\n  },\n  "image/apng": {\n    "compressible": false,\n    "extensions": ["apng"]\n  },\n  "image/avci": {\n    "source": "iana"\n  },\n  "image/avcs": {\n    "source": "iana"\n  },\n  "image/avif": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["avif"]\n  },\n  "image/bmp": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["bmp"]\n  },\n  "image/cgm": {\n    "source": "iana",\n    "extensions": ["cgm"]\n  },\n  "image/dicom-rle": {\n    "source": "iana",\n    "extensions": ["drle"]\n  },\n  "image/emf": {\n    "source": "iana",\n    "extensions": ["emf"]\n  },\n  "image/fits": {\n    "source": "iana",\n    "extensions": ["fits"]\n  },\n  "image/g3fax": {\n    "source": "iana",\n    "extensions": ["g3"]\n  },\n  "image/gif": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["gif"]\n  },\n  "image/heic": {\n    "source": "iana",\n    "extensions": ["heic"]\n  },\n  "image/heic-sequence": {\n    "source": "iana",\n    "extensions": ["heics"]\n  },\n  "image/heif": {\n    "source": "iana",\n    "extensions": ["heif"]\n  },\n  "image/heif-sequence": {\n    "source": "iana",\n    "extensions": ["heifs"]\n  },\n  "image/hej2k": {\n    "source": "iana",\n    "extensions": ["hej2"]\n  },\n  "image/hsj2": {\n    "source": "iana",\n    "extensions": ["hsj2"]\n  },\n  "image/ief": {\n    "source": "iana",\n    "extensions": ["ief"]\n  },\n  "image/jls": {\n    "source": "iana",\n    "extensions": ["jls"]\n  },\n  "image/jp2": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jp2","jpg2"]\n  },\n  "image/jpeg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jpeg","jpg","jpe"]\n  },\n  "image/jph": {\n    "source": "iana",\n    "extensions": ["jph"]\n  },\n  "image/jphc": {\n    "source": "iana",\n    "extensions": ["jhc"]\n  },\n  "image/jpm": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jpm"]\n  },\n  "image/jpx": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jpx","jpf"]\n  },\n  "image/jxr": {\n    "source": "iana",\n    "extensions": ["jxr"]\n  },\n  "image/jxra": {\n    "source": "iana",\n    "extensions": ["jxra"]\n  },\n  "image/jxrs": {\n    "source": "iana",\n    "extensions": ["jxrs"]\n  },\n  "image/jxs": {\n    "source": "iana",\n    "extensions": ["jxs"]\n  },\n  "image/jxsc": {\n    "source": "iana",\n    "extensions": ["jxsc"]\n  },\n  "image/jxsi": {\n    "source": "iana",\n    "extensions": ["jxsi"]\n  },\n  "image/jxss": {\n    "source": "iana",\n    "extensions": ["jxss"]\n  },\n  "image/ktx": {\n    "source": "iana",\n    "extensions": ["ktx"]\n  },\n  "image/ktx2": {\n    "source": "iana",\n    "extensions": ["ktx2"]\n  },\n  "image/naplps": {\n    "source": "iana"\n  },\n  "image/pjpeg": {\n    "compressible": false\n  },\n  "image/png": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["png"]\n  },\n  "image/prs.btif": {\n    "source": "iana",\n    "extensions": ["btif"]\n  },\n  "image/prs.pti": {\n    "source": "iana",\n    "extensions": ["pti"]\n  },\n  "image/pwg-raster": {\n    "source": "iana"\n  },\n  "image/sgi": {\n    "source": "apache",\n    "extensions": ["sgi"]\n  },\n  "image/svg+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["svg","svgz"]\n  },\n  "image/t38": {\n    "source": "iana",\n    "extensions": ["t38"]\n  },\n  "image/tiff": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["tif","tiff"]\n  },\n  "image/tiff-fx": {\n    "source": "iana",\n    "extensions": ["tfx"]\n  },\n  "image/vnd.adobe.photoshop": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["psd"]\n  },\n  "image/vnd.airzip.accelerator.azv": {\n    "source": "iana",\n    "extensions": ["azv"]\n  },\n  "image/vnd.cns.inf2": {\n    "source": "iana"\n  },\n  "image/vnd.dece.graphic": {\n    "source": "iana",\n    "extensions": ["uvi","uvvi","uvg","uvvg"]\n  },\n  "image/vnd.djvu": {\n    "source": "iana",\n    "extensions": ["djvu","djv"]\n  },\n  "image/vnd.dvb.subtitle": {\n    "source": "iana",\n    "extensions": ["sub"]\n  },\n  "image/vnd.dwg": {\n    "source": "iana",\n    "extensions": ["dwg"]\n  },\n  "image/vnd.dxf": {\n    "source": "iana",\n    "extensions": ["dxf"]\n  },\n  "image/vnd.fastbidsheet": {\n    "source": "iana",\n    "extensions": ["fbs"]\n  },\n  "image/vnd.fpx": {\n    "source": "iana",\n    "extensions": ["fpx"]\n  },\n  "image/vnd.fst": {\n    "source": "iana",\n    "extensions": ["fst"]\n  },\n  "image/vnd.fujixerox.edmics-mmr": {\n    "source": "iana",\n    "extensions": ["mmr"]\n  },\n  "image/vnd.fujixerox.edmics-rlc": {\n    "source": "iana",\n    "extensions": ["rlc"]\n  },\n  "image/vnd.globalgraphics.pgb": {\n    "source": "iana"\n  },\n  "image/vnd.microsoft.icon": {\n    "source": "iana",\n    "extensions": ["ico"]\n  },\n  "image/vnd.mix": {\n    "source": "iana"\n  },\n  "image/vnd.mozilla.apng": {\n    "source": "iana"\n  },\n  "image/vnd.ms-dds": {\n    "extensions": ["dds"]\n  },\n  "image/vnd.ms-modi": {\n    "source": "iana",\n    "extensions": ["mdi"]\n  },\n  "image/vnd.ms-photo": {\n    "source": "apache",\n    "extensions": ["wdp"]\n  },\n  "image/vnd.net-fpx": {\n    "source": "iana",\n    "extensions": ["npx"]\n  },\n  "image/vnd.pco.b16": {\n    "source": "iana",\n    "extensions": ["b16"]\n  },\n  "image/vnd.radiance": {\n    "source": "iana"\n  },\n  "image/vnd.sealed.png": {\n    "source": "iana"\n  },\n  "image/vnd.sealedmedia.softseal.gif": {\n    "source": "iana"\n  },\n  "image/vnd.sealedmedia.softseal.jpg": {\n    "source": "iana"\n  },\n  "image/vnd.svf": {\n    "source": "iana"\n  },\n  "image/vnd.tencent.tap": {\n    "source": "iana",\n    "extensions": ["tap"]\n  },\n  "image/vnd.valve.source.texture": {\n    "source": "iana",\n    "extensions": ["vtf"]\n  },\n  "image/vnd.wap.wbmp": {\n    "source": "iana",\n    "extensions": ["wbmp"]\n  },\n  "image/vnd.xiff": {\n    "source": "iana",\n    "extensions": ["xif"]\n  },\n  "image/vnd.zbrush.pcx": {\n    "source": "iana",\n    "extensions": ["pcx"]\n  },\n  "image/webp": {\n    "source": "apache",\n    "extensions": ["webp"]\n  },\n  "image/wmf": {\n    "source": "iana",\n    "extensions": ["wmf"]\n  },\n  "image/x-3ds": {\n    "source": "apache",\n    "extensions": ["3ds"]\n  },\n  "image/x-cmu-raster": {\n    "source": "apache",\n    "extensions": ["ras"]\n  },\n  "image/x-cmx": {\n    "source": "apache",\n    "extensions": ["cmx"]\n  },\n  "image/x-freehand": {\n    "source": "apache",\n    "extensions": ["fh","fhc","fh4","fh5","fh7"]\n  },\n  "image/x-icon": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["ico"]\n  },\n  "image/x-jng": {\n    "source": "nginx",\n    "extensions": ["jng"]\n  },\n  "image/x-mrsid-image": {\n    "source": "apache",\n    "extensions": ["sid"]\n  },\n  "image/x-ms-bmp": {\n    "source": "nginx",\n    "compressible": true,\n    "extensions": ["bmp"]\n  },\n  "image/x-pcx": {\n    "source": "apache",\n    "extensions": ["pcx"]\n  },\n  "image/x-pict": {\n    "source": "apache",\n    "extensions": ["pic","pct"]\n  },\n  "image/x-portable-anymap": {\n    "source": "apache",\n    "extensions": ["pnm"]\n  },\n  "image/x-portable-bitmap": {\n    "source": "apache",\n    "extensions": ["pbm"]\n  },\n  "image/x-portable-graymap": {\n    "source": "apache",\n    "extensions": ["pgm"]\n  },\n  "image/x-portable-pixmap": {\n    "source": "apache",\n    "extensions": ["ppm"]\n  },\n  "image/x-rgb": {\n    "source": "apache",\n    "extensions": ["rgb"]\n  },\n  "image/x-tga": {\n    "source": "apache",\n    "extensions": ["tga"]\n  },\n  "image/x-xbitmap": {\n    "source": "apache",\n    "extensions": ["xbm"]\n  },\n  "image/x-xcf": {\n    "compressible": false\n  },\n  "image/x-xpixmap": {\n    "source": "apache",\n    "extensions": ["xpm"]\n  },\n  "image/x-xwindowdump": {\n    "source": "apache",\n    "extensions": ["xwd"]\n  },\n  "message/cpim": {\n    "source": "iana"\n  },\n  "message/delivery-status": {\n    "source": "iana"\n  },\n  "message/disposition-notification": {\n    "source": "iana",\n    "extensions": [\n      "disposition-notification"\n    ]\n  },\n  "message/external-body": {\n    "source": "iana"\n  },\n  "message/feedback-report": {\n    "source": "iana"\n  },\n  "message/global": {\n    "source": "iana",\n    "extensions": ["u8msg"]\n  },\n  "message/global-delivery-status": {\n    "source": "iana",\n    "extensions": ["u8dsn"]\n  },\n  "message/global-disposition-notification": {\n    "source": "iana",\n    "extensions": ["u8mdn"]\n  },\n  "message/global-headers": {\n    "source": "iana",\n    "extensions": ["u8hdr"]\n  },\n  "message/http": {\n    "source": "iana",\n    "compressible": false\n  },\n  "message/imdn+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "message/news": {\n    "source": "iana"\n  },\n  "message/partial": {\n    "source": "iana",\n    "compressible": false\n  },\n  "message/rfc822": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["eml","mime"]\n  },\n  "message/s-http": {\n    "source": "iana"\n  },\n  "message/sip": {\n    "source": "iana"\n  },\n  "message/sipfrag": {\n    "source": "iana"\n  },\n  "message/tracking-status": {\n    "source": "iana"\n  },\n  "message/vnd.si.simp": {\n    "source": "iana"\n  },\n  "message/vnd.wfa.wsc": {\n    "source": "iana",\n    "extensions": ["wsc"]\n  },\n  "model/3mf": {\n    "source": "iana",\n    "extensions": ["3mf"]\n  },\n  "model/e57": {\n    "source": "iana"\n  },\n  "model/gltf+json": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["gltf"]\n  },\n  "model/gltf-binary": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["glb"]\n  },\n  "model/iges": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["igs","iges"]\n  },\n  "model/mesh": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["msh","mesh","silo"]\n  },\n  "model/mtl": {\n    "source": "iana",\n    "extensions": ["mtl"]\n  },\n  "model/obj": {\n    "source": "iana",\n    "extensions": ["obj"]\n  },\n  "model/stl": {\n    "source": "iana",\n    "extensions": ["stl"]\n  },\n  "model/vnd.collada+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dae"]\n  },\n  "model/vnd.dwf": {\n    "source": "iana",\n    "extensions": ["dwf"]\n  },\n  "model/vnd.flatland.3dml": {\n    "source": "iana"\n  },\n  "model/vnd.gdl": {\n    "source": "iana",\n    "extensions": ["gdl"]\n  },\n  "model/vnd.gs-gdl": {\n    "source": "apache"\n  },\n  "model/vnd.gs.gdl": {\n    "source": "iana"\n  },\n  "model/vnd.gtw": {\n    "source": "iana",\n    "extensions": ["gtw"]\n  },\n  "model/vnd.moml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "model/vnd.mts": {\n    "source": "iana",\n    "extensions": ["mts"]\n  },\n  "model/vnd.opengex": {\n    "source": "iana",\n    "extensions": ["ogex"]\n  },\n  "model/vnd.parasolid.transmit.binary": {\n    "source": "iana",\n    "extensions": ["x_b"]\n  },\n  "model/vnd.parasolid.transmit.text": {\n    "source": "iana",\n    "extensions": ["x_t"]\n  },\n  "model/vnd.pytha.pyox": {\n    "source": "iana"\n  },\n  "model/vnd.rosette.annotated-data-model": {\n    "source": "iana"\n  },\n  "model/vnd.sap.vds": {\n    "source": "iana",\n    "extensions": ["vds"]\n  },\n  "model/vnd.usdz+zip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["usdz"]\n  },\n  "model/vnd.valve.source.compiled-map": {\n    "source": "iana",\n    "extensions": ["bsp"]\n  },\n  "model/vnd.vtu": {\n    "source": "iana",\n    "extensions": ["vtu"]\n  },\n  "model/vrml": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["wrl","vrml"]\n  },\n  "model/x3d+binary": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["x3db","x3dbz"]\n  },\n  "model/x3d+fastinfoset": {\n    "source": "iana",\n    "extensions": ["x3db"]\n  },\n  "model/x3d+vrml": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["x3dv","x3dvz"]\n  },\n  "model/x3d+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["x3d","x3dz"]\n  },\n  "model/x3d-vrml": {\n    "source": "iana",\n    "extensions": ["x3dv"]\n  },\n  "multipart/alternative": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/appledouble": {\n    "source": "iana"\n  },\n  "multipart/byteranges": {\n    "source": "iana"\n  },\n  "multipart/digest": {\n    "source": "iana"\n  },\n  "multipart/encrypted": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/form-data": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/header-set": {\n    "source": "iana"\n  },\n  "multipart/mixed": {\n    "source": "iana"\n  },\n  "multipart/multilingual": {\n    "source": "iana"\n  },\n  "multipart/parallel": {\n    "source": "iana"\n  },\n  "multipart/related": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/report": {\n    "source": "iana"\n  },\n  "multipart/signed": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/vnd.bint.med-plus": {\n    "source": "iana"\n  },\n  "multipart/voice-message": {\n    "source": "iana"\n  },\n  "multipart/x-mixed-replace": {\n    "source": "iana"\n  },\n  "text/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "text/cache-manifest": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["appcache","manifest"]\n  },\n  "text/calendar": {\n    "source": "iana",\n    "extensions": ["ics","ifb"]\n  },\n  "text/calender": {\n    "compressible": true\n  },\n  "text/cmd": {\n    "compressible": true\n  },\n  "text/coffeescript": {\n    "extensions": ["coffee","litcoffee"]\n  },\n  "text/cql": {\n    "source": "iana"\n  },\n  "text/cql-expression": {\n    "source": "iana"\n  },\n  "text/cql-identifier": {\n    "source": "iana"\n  },\n  "text/css": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["css"]\n  },\n  "text/csv": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["csv"]\n  },\n  "text/csv-schema": {\n    "source": "iana"\n  },\n  "text/directory": {\n    "source": "iana"\n  },\n  "text/dns": {\n    "source": "iana"\n  },\n  "text/ecmascript": {\n    "source": "iana"\n  },\n  "text/encaprtp": {\n    "source": "iana"\n  },\n  "text/enriched": {\n    "source": "iana"\n  },\n  "text/fhirpath": {\n    "source": "iana"\n  },\n  "text/flexfec": {\n    "source": "iana"\n  },\n  "text/fwdred": {\n    "source": "iana"\n  },\n  "text/gff3": {\n    "source": "iana"\n  },\n  "text/grammar-ref-list": {\n    "source": "iana"\n  },\n  "text/html": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["html","htm","shtml"]\n  },\n  "text/jade": {\n    "extensions": ["jade"]\n  },\n  "text/javascript": {\n    "source": "iana",\n    "compressible": true\n  },\n  "text/jcr-cnd": {\n    "source": "iana"\n  },\n  "text/jsx": {\n    "compressible": true,\n    "extensions": ["jsx"]\n  },\n  "text/less": {\n    "compressible": true,\n    "extensions": ["less"]\n  },\n  "text/markdown": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["markdown","md"]\n  },\n  "text/mathml": {\n    "source": "nginx",\n    "extensions": ["mml"]\n  },\n  "text/mdx": {\n    "compressible": true,\n    "extensions": ["mdx"]\n  },\n  "text/mizar": {\n    "source": "iana"\n  },\n  "text/n3": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["n3"]\n  },\n  "text/parameters": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/parityfec": {\n    "source": "iana"\n  },\n  "text/plain": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["txt","text","conf","def","list","log","in","ini"]\n  },\n  "text/provenance-notation": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/prs.fallenstein.rst": {\n    "source": "iana"\n  },\n  "text/prs.lines.tag": {\n    "source": "iana",\n    "extensions": ["dsc"]\n  },\n  "text/prs.prop.logic": {\n    "source": "iana"\n  },\n  "text/raptorfec": {\n    "source": "iana"\n  },\n  "text/red": {\n    "source": "iana"\n  },\n  "text/rfc822-headers": {\n    "source": "iana"\n  },\n  "text/richtext": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rtx"]\n  },\n  "text/rtf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rtf"]\n  },\n  "text/rtp-enc-aescm128": {\n    "source": "iana"\n  },\n  "text/rtploopback": {\n    "source": "iana"\n  },\n  "text/rtx": {\n    "source": "iana"\n  },\n  "text/sgml": {\n    "source": "iana",\n    "extensions": ["sgml","sgm"]\n  },\n  "text/shaclc": {\n    "source": "iana"\n  },\n  "text/shex": {\n    "source": "iana",\n    "extensions": ["shex"]\n  },\n  "text/slim": {\n    "extensions": ["slim","slm"]\n  },\n  "text/spdx": {\n    "source": "iana",\n    "extensions": ["spdx"]\n  },\n  "text/strings": {\n    "source": "iana"\n  },\n  "text/stylus": {\n    "extensions": ["stylus","styl"]\n  },\n  "text/t140": {\n    "source": "iana"\n  },\n  "text/tab-separated-values": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["tsv"]\n  },\n  "text/troff": {\n    "source": "iana",\n    "extensions": ["t","tr","roff","man","me","ms"]\n  },\n  "text/turtle": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["ttl"]\n  },\n  "text/ulpfec": {\n    "source": "iana"\n  },\n  "text/uri-list": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["uri","uris","urls"]\n  },\n  "text/vcard": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["vcard"]\n  },\n  "text/vnd.a": {\n    "source": "iana"\n  },\n  "text/vnd.abc": {\n    "source": "iana"\n  },\n  "text/vnd.ascii-art": {\n    "source": "iana"\n  },\n  "text/vnd.curl": {\n    "source": "iana",\n    "extensions": ["curl"]\n  },\n  "text/vnd.curl.dcurl": {\n    "source": "apache",\n    "extensions": ["dcurl"]\n  },\n  "text/vnd.curl.mcurl": {\n    "source": "apache",\n    "extensions": ["mcurl"]\n  },\n  "text/vnd.curl.scurl": {\n    "source": "apache",\n    "extensions": ["scurl"]\n  },\n  "text/vnd.debian.copyright": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/vnd.dmclientscript": {\n    "source": "iana"\n  },\n  "text/vnd.dvb.subtitle": {\n    "source": "iana",\n    "extensions": ["sub"]\n  },\n  "text/vnd.esmertec.theme-descriptor": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/vnd.ficlab.flt": {\n    "source": "iana"\n  },\n  "text/vnd.fly": {\n    "source": "iana",\n    "extensions": ["fly"]\n  },\n  "text/vnd.fmi.flexstor": {\n    "source": "iana",\n    "extensions": ["flx"]\n  },\n  "text/vnd.gml": {\n    "source": "iana"\n  },\n  "text/vnd.graphviz": {\n    "source": "iana",\n    "extensions": ["gv"]\n  },\n  "text/vnd.hans": {\n    "source": "iana"\n  },\n  "text/vnd.hgl": {\n    "source": "iana"\n  },\n  "text/vnd.in3d.3dml": {\n    "source": "iana",\n    "extensions": ["3dml"]\n  },\n  "text/vnd.in3d.spot": {\n    "source": "iana",\n    "extensions": ["spot"]\n  },\n  "text/vnd.iptc.newsml": {\n    "source": "iana"\n  },\n  "text/vnd.iptc.nitf": {\n    "source": "iana"\n  },\n  "text/vnd.latex-z": {\n    "source": "iana"\n  },\n  "text/vnd.motorola.reflex": {\n    "source": "iana"\n  },\n  "text/vnd.ms-mediapackage": {\n    "source": "iana"\n  },\n  "text/vnd.net2phone.commcenter.command": {\n    "source": "iana"\n  },\n  "text/vnd.radisys.msml-basic-layout": {\n    "source": "iana"\n  },\n  "text/vnd.senx.warpscript": {\n    "source": "iana"\n  },\n  "text/vnd.si.uricatalogue": {\n    "source": "iana"\n  },\n  "text/vnd.sosi": {\n    "source": "iana"\n  },\n  "text/vnd.sun.j2me.app-descriptor": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["jad"]\n  },\n  "text/vnd.trolltech.linguist": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/vnd.wap.si": {\n    "source": "iana"\n  },\n  "text/vnd.wap.sl": {\n    "source": "iana"\n  },\n  "text/vnd.wap.wml": {\n    "source": "iana",\n    "extensions": ["wml"]\n  },\n  "text/vnd.wap.wmlscript": {\n    "source": "iana",\n    "extensions": ["wmls"]\n  },\n  "text/vtt": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["vtt"]\n  },\n  "text/x-asm": {\n    "source": "apache",\n    "extensions": ["s","asm"]\n  },\n  "text/x-c": {\n    "source": "apache",\n    "extensions": ["c","cc","cxx","cpp","h","hh","dic"]\n  },\n  "text/x-component": {\n    "source": "nginx",\n    "extensions": ["htc"]\n  },\n  "text/x-fortran": {\n    "source": "apache",\n    "extensions": ["f","for","f77","f90"]\n  },\n  "text/x-gwt-rpc": {\n    "compressible": true\n  },\n  "text/x-handlebars-template": {\n    "extensions": ["hbs"]\n  },\n  "text/x-java-source": {\n    "source": "apache",\n    "extensions": ["java"]\n  },\n  "text/x-jquery-tmpl": {\n    "compressible": true\n  },\n  "text/x-lua": {\n    "extensions": ["lua"]\n  },\n  "text/x-markdown": {\n    "compressible": true,\n    "extensions": ["mkd"]\n  },\n  "text/x-nfo": {\n    "source": "apache",\n    "extensions": ["nfo"]\n  },\n  "text/x-opml": {\n    "source": "apache",\n    "extensions": ["opml"]\n  },\n  "text/x-org": {\n    "compressible": true,\n    "extensions": ["org"]\n  },\n  "text/x-pascal": {\n    "source": "apache",\n    "extensions": ["p","pas"]\n  },\n  "text/x-processing": {\n    "compressible": true,\n    "extensions": ["pde"]\n  },\n  "text/x-sass": {\n    "extensions": ["sass"]\n  },\n  "text/x-scss": {\n    "extensions": ["scss"]\n  },\n  "text/x-setext": {\n    "source": "apache",\n    "extensions": ["etx"]\n  },\n  "text/x-sfv": {\n    "source": "apache",\n    "extensions": ["sfv"]\n  },\n  "text/x-suse-ymp": {\n    "compressible": true,\n    "extensions": ["ymp"]\n  },\n  "text/x-uuencode": {\n    "source": "apache",\n    "extensions": ["uu"]\n  },\n  "text/x-vcalendar": {\n    "source": "apache",\n    "extensions": ["vcs"]\n  },\n  "text/x-vcard": {\n    "source": "apache",\n    "extensions": ["vcf"]\n  },\n  "text/xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xml"]\n  },\n  "text/xml-external-parsed-entity": {\n    "source": "iana"\n  },\n  "text/yaml": {\n    "compressible": true,\n    "extensions": ["yaml","yml"]\n  },\n  "video/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "video/3gpp": {\n    "source": "iana",\n    "extensions": ["3gp","3gpp"]\n  },\n  "video/3gpp-tt": {\n    "source": "iana"\n  },\n  "video/3gpp2": {\n    "source": "iana",\n    "extensions": ["3g2"]\n  },\n  "video/av1": {\n    "source": "iana"\n  },\n  "video/bmpeg": {\n    "source": "iana"\n  },\n  "video/bt656": {\n    "source": "iana"\n  },\n  "video/celb": {\n    "source": "iana"\n  },\n  "video/dv": {\n    "source": "iana"\n  },\n  "video/encaprtp": {\n    "source": "iana"\n  },\n  "video/ffv1": {\n    "source": "iana"\n  },\n  "video/flexfec": {\n    "source": "iana"\n  },\n  "video/h261": {\n    "source": "iana",\n    "extensions": ["h261"]\n  },\n  "video/h263": {\n    "source": "iana",\n    "extensions": ["h263"]\n  },\n  "video/h263-1998": {\n    "source": "iana"\n  },\n  "video/h263-2000": {\n    "source": "iana"\n  },\n  "video/h264": {\n    "source": "iana",\n    "extensions": ["h264"]\n  },\n  "video/h264-rcdo": {\n    "source": "iana"\n  },\n  "video/h264-svc": {\n    "source": "iana"\n  },\n  "video/h265": {\n    "source": "iana"\n  },\n  "video/iso.segment": {\n    "source": "iana",\n    "extensions": ["m4s"]\n  },\n  "video/jpeg": {\n    "source": "iana",\n    "extensions": ["jpgv"]\n  },\n  "video/jpeg2000": {\n    "source": "iana"\n  },\n  "video/jpm": {\n    "source": "apache",\n    "extensions": ["jpm","jpgm"]\n  },\n  "video/mj2": {\n    "source": "iana",\n    "extensions": ["mj2","mjp2"]\n  },\n  "video/mp1s": {\n    "source": "iana"\n  },\n  "video/mp2p": {\n    "source": "iana"\n  },\n  "video/mp2t": {\n    "source": "iana",\n    "extensions": ["ts"]\n  },\n  "video/mp4": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["mp4","mp4v","mpg4"]\n  },\n  "video/mp4v-es": {\n    "source": "iana"\n  },\n  "video/mpeg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["mpeg","mpg","mpe","m1v","m2v"]\n  },\n  "video/mpeg4-generic": {\n    "source": "iana"\n  },\n  "video/mpv": {\n    "source": "iana"\n  },\n  "video/nv": {\n    "source": "iana"\n  },\n  "video/ogg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ogv"]\n  },\n  "video/parityfec": {\n    "source": "iana"\n  },\n  "video/pointer": {\n    "source": "iana"\n  },\n  "video/quicktime": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["qt","mov"]\n  },\n  "video/raptorfec": {\n    "source": "iana"\n  },\n  "video/raw": {\n    "source": "iana"\n  },\n  "video/rtp-enc-aescm128": {\n    "source": "iana"\n  },\n  "video/rtploopback": {\n    "source": "iana"\n  },\n  "video/rtx": {\n    "source": "iana"\n  },\n  "video/scip": {\n    "source": "iana"\n  },\n  "video/smpte291": {\n    "source": "iana"\n  },\n  "video/smpte292m": {\n    "source": "iana"\n  },\n  "video/ulpfec": {\n    "source": "iana"\n  },\n  "video/vc1": {\n    "source": "iana"\n  },\n  "video/vc2": {\n    "source": "iana"\n  },\n  "video/vnd.cctv": {\n    "source": "iana"\n  },\n  "video/vnd.dece.hd": {\n    "source": "iana",\n    "extensions": ["uvh","uvvh"]\n  },\n  "video/vnd.dece.mobile": {\n    "source": "iana",\n    "extensions": ["uvm","uvvm"]\n  },\n  "video/vnd.dece.mp4": {\n    "source": "iana"\n  },\n  "video/vnd.dece.pd": {\n    "source": "iana",\n    "extensions": ["uvp","uvvp"]\n  },\n  "video/vnd.dece.sd": {\n    "source": "iana",\n    "extensions": ["uvs","uvvs"]\n  },\n  "video/vnd.dece.video": {\n    "source": "iana",\n    "extensions": ["uvv","uvvv"]\n  },\n  "video/vnd.directv.mpeg": {\n    "source": "iana"\n  },\n  "video/vnd.directv.mpeg-tts": {\n    "source": "iana"\n  },\n  "video/vnd.dlna.mpeg-tts": {\n    "source": "iana"\n  },\n  "video/vnd.dvb.file": {\n    "source": "iana",\n    "extensions": ["dvb"]\n  },\n  "video/vnd.fvt": {\n    "source": "iana",\n    "extensions": ["fvt"]\n  },\n  "video/vnd.hns.video": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.1dparityfec-1010": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.1dparityfec-2005": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.2dparityfec-1010": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.2dparityfec-2005": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.ttsavc": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.ttsmpeg2": {\n    "source": "iana"\n  },\n  "video/vnd.motorola.video": {\n    "source": "iana"\n  },\n  "video/vnd.motorola.videop": {\n    "source": "iana"\n  },\n  "video/vnd.mpegurl": {\n    "source": "iana",\n    "extensions": ["mxu","m4u"]\n  },\n  "video/vnd.ms-playready.media.pyv": {\n    "source": "iana",\n    "extensions": ["pyv"]\n  },\n  "video/vnd.nokia.interleaved-multimedia": {\n    "source": "iana"\n  },\n  "video/vnd.nokia.mp4vr": {\n    "source": "iana"\n  },\n  "video/vnd.nokia.videovoip": {\n    "source": "iana"\n  },\n  "video/vnd.objectvideo": {\n    "source": "iana"\n  },\n  "video/vnd.radgamettools.bink": {\n    "source": "iana"\n  },\n  "video/vnd.radgamettools.smacker": {\n    "source": "iana"\n  },\n  "video/vnd.sealed.mpeg1": {\n    "source": "iana"\n  },\n  "video/vnd.sealed.mpeg4": {\n    "source": "iana"\n  },\n  "video/vnd.sealed.swf": {\n    "source": "iana"\n  },\n  "video/vnd.sealedmedia.softseal.mov": {\n    "source": "iana"\n  },\n  "video/vnd.uvvu.mp4": {\n    "source": "iana",\n    "extensions": ["uvu","uvvu"]\n  },\n  "video/vnd.vivo": {\n    "source": "iana",\n    "extensions": ["viv"]\n  },\n  "video/vnd.youtube.yt": {\n    "source": "iana"\n  },\n  "video/vp8": {\n    "source": "iana"\n  },\n  "video/webm": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["webm"]\n  },\n  "video/x-f4v": {\n    "source": "apache",\n    "extensions": ["f4v"]\n  },\n  "video/x-fli": {\n    "source": "apache",\n    "extensions": ["fli"]\n  },\n  "video/x-flv": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["flv"]\n  },\n  "video/x-m4v": {\n    "source": "apache",\n    "extensions": ["m4v"]\n  },\n  "video/x-matroska": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["mkv","mk3d","mks"]\n  },\n  "video/x-mng": {\n    "source": "apache",\n    "extensions": ["mng"]\n  },\n  "video/x-ms-asf": {\n    "source": "apache",\n    "extensions": ["asf","asx"]\n  },\n  "video/x-ms-vob": {\n    "source": "apache",\n    "extensions": ["vob"]\n  },\n  "video/x-ms-wm": {\n    "source": "apache",\n    "extensions": ["wm"]\n  },\n  "video/x-ms-wmv": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["wmv"]\n  },\n  "video/x-ms-wmx": {\n    "source": "apache",\n    "extensions": ["wmx"]\n  },\n  "video/x-ms-wvx": {\n    "source": "apache",\n    "extensions": ["wvx"]\n  },\n  "video/x-msvideo": {\n    "source": "apache",\n    "extensions": ["avi"]\n  },\n  "video/x-sgi-movie": {\n    "source": "apache",\n    "extensions": ["movie"]\n  },\n  "video/x-smv": {\n    "source": "apache",\n    "extensions": ["smv"]\n  },\n  "x-conference/x-cooltalk": {\n    "source": "apache",\n    "extensions": ["ice"]\n  },\n  "x-shader/x-fragment": {\n    "compressible": true\n  },\n  "x-shader/x-vertex": {\n    "compressible": true\n  }\n}`);
const EXTRACT_TYPE_REGEXP = /^\s*([^;\s]*)(?:;|\s|$)/;
const TEXT_TYPE_REGEXP = /^text\//i;
const extensions = new Map();
const types1 = new Map();
function populateMaps(extensions1, types1) {
    const preference = [
        "nginx",
        "apache",
        undefined,
        "iana"
    ];
    for (const type of Object.keys(db)){
        const mime = db[type];
        const exts = mime.extensions;
        if (!exts || !exts.length) {
            continue;
        }
        extensions1.set(type, exts);
        for (const ext of exts){
            const current = types1.get(ext);
            if (current) {
                const from = preference.indexOf(db[current].source);
                const to = preference.indexOf(mime.source);
                if (current !== "application/octet-stream" && (from > to || from === to && current.substr(0, 12) === "application/")) {
                    continue;
                }
            }
            types1.set(ext, type);
        }
    }
}
populateMaps(extensions, types1);
function charset(type) {
    const m = EXTRACT_TYPE_REGEXP.exec(type);
    if (!m) {
        return undefined;
    }
    const [match] = m;
    const mime = db[match.toLowerCase()];
    if (mime && mime.charset) {
        return mime.charset;
    }
    if (TEXT_TYPE_REGEXP.test(match)) {
        return "UTF-8";
    }
    return undefined;
}
function lookup(path1) {
    const extension = extname2("x." + path1).toLowerCase().substr(1);
    return types1.get(extension);
}
function contentType(str1) {
    let mime = str1.includes("/") ? str1 : lookup(str1);
    if (!mime) {
        return undefined;
    }
    if (!mime.includes("charset")) {
        const cs = charset(mime);
        if (cs) {
            mime += `; charset=${cs.toLowerCase()}`;
        }
    }
    return mime;
}
function extension(type) {
    const match = EXTRACT_TYPE_REGEXP.exec(type);
    if (!match) {
        return undefined;
    }
    const exts = extensions.get(match[1].toLowerCase());
    if (!exts || !exts.length) {
        return undefined;
    }
    return exts[0];
}
function lexer(str1) {
    const tokens = [];
    let i2 = 0;
    while(i2 < str1.length){
        const __char = str1[i2];
        if (__char === "*" || __char === "+" || __char === "?") {
            tokens.push({
                type: "MODIFIER",
                index: i2,
                value: str1[i2++]
            });
            continue;
        }
        if (__char === "\\") {
            tokens.push({
                type: "ESCAPED_CHAR",
                index: i2++,
                value: str1[i2++]
            });
            continue;
        }
        if (__char === "{") {
            tokens.push({
                type: "OPEN",
                index: i2,
                value: str1[i2++]
            });
            continue;
        }
        if (__char === "}") {
            tokens.push({
                type: "CLOSE",
                index: i2,
                value: str1[i2++]
            });
            continue;
        }
        if (__char === ":") {
            let name2 = "";
            let j = i2 + 1;
            while(j < str1.length){
                const code = str1.charCodeAt(j);
                if (code >= 48 && code <= 57 || code >= 65 && code <= 90 || code >= 97 && code <= 122 || code === 95) {
                    name2 += str1[j++];
                    continue;
                }
                break;
            }
            if (!name2) throw new TypeError(`Missing parameter name at ${i2}`);
            tokens.push({
                type: "NAME",
                index: i2,
                value: name2
            });
            i2 = j;
            continue;
        }
        if (__char === "(") {
            let count = 1;
            let pattern = "";
            let j = i2 + 1;
            if (str1[j] === "?") {
                throw new TypeError(`Pattern cannot start with "?" at ${j}`);
            }
            while(j < str1.length){
                if (str1[j] === "\\") {
                    pattern += str1[j++] + str1[j++];
                    continue;
                }
                if (str1[j] === ")") {
                    count--;
                    if (count === 0) {
                        j++;
                        break;
                    }
                } else if (str1[j] === "(") {
                    count++;
                    if (str1[j + 1] !== "?") {
                        throw new TypeError(`Capturing groups are not allowed at ${j}`);
                    }
                }
                pattern += str1[j++];
            }
            if (count) throw new TypeError(`Unbalanced pattern at ${i2}`);
            if (!pattern) throw new TypeError(`Missing pattern at ${i2}`);
            tokens.push({
                type: "PATTERN",
                index: i2,
                value: pattern
            });
            i2 = j;
            continue;
        }
        tokens.push({
            type: "CHAR",
            index: i2,
            value: str1[i2++]
        });
    }
    tokens.push({
        type: "END",
        index: i2,
        value: ""
    });
    return tokens;
}
function parse3(str1, options2 = {
}) {
    const tokens = lexer(str1);
    const { prefixes ="./"  } = options2;
    const defaultPattern = `[^${escapeString(options2.delimiter || "/#?")}]+?`;
    const result = [];
    let key2 = 0;
    let i2 = 0;
    let path1 = "";
    const tryConsume = (type)=>{
        if (i2 < tokens.length && tokens[i2].type === type) return tokens[i2++].value;
    };
    const mustConsume = (type)=>{
        const value2 = tryConsume(type);
        if (value2 !== undefined) return value2;
        const { type: nextType , index  } = tokens[i2];
        throw new TypeError(`Unexpected ${nextType} at ${index}, expected ${type}`);
    };
    const consumeText = ()=>{
        let result1 = "";
        let value2;
        while(value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")){
            result1 += value2;
        }
        return result1;
    };
    while(i2 < tokens.length){
        const __char = tryConsume("CHAR");
        const name2 = tryConsume("NAME");
        const pattern = tryConsume("PATTERN");
        if (name2 || pattern) {
            let prefix = __char || "";
            if (prefixes.indexOf(prefix) === -1) {
                path1 += prefix;
                prefix = "";
            }
            if (path1) {
                result.push(path1);
                path1 = "";
            }
            result.push({
                name: name2 || key2++,
                prefix,
                suffix: "",
                pattern: pattern || defaultPattern,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        const value2 = __char || tryConsume("ESCAPED_CHAR");
        if (value2) {
            path1 += value2;
            continue;
        }
        if (path1) {
            result.push(path1);
            path1 = "";
        }
        const open = tryConsume("OPEN");
        if (open) {
            const prefix = consumeText();
            const name3 = tryConsume("NAME") || "";
            const pattern1 = tryConsume("PATTERN") || "";
            const suffix = consumeText();
            mustConsume("CLOSE");
            result.push({
                name: name3 || (pattern1 ? key2++ : ""),
                pattern: name3 && !pattern1 ? defaultPattern : pattern1,
                prefix,
                suffix,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        mustConsume("END");
    }
    return result;
}
function compile(str1, options2) {
    return tokensToFunction(parse3(str1, options2), options2);
}
function tokensToFunction(tokens, options2 = {
}) {
    const reFlags = flags(options2);
    const { encode: encode2 = (x)=>x
     , validate =true  } = options2;
    const matches = tokens.map((token)=>{
        if (typeof token === "object") {
            return new RegExp(`^(?:${token.pattern})$`, reFlags);
        }
    });
    return (data)=>{
        let path1 = "";
        for(let i2 = 0; i2 < tokens.length; i2++){
            const token = tokens[i2];
            if (typeof token === "string") {
                path1 += token;
                continue;
            }
            const value2 = data ? data[token.name] : undefined;
            const optional = token.modifier === "?" || token.modifier === "*";
            const repeat = token.modifier === "*" || token.modifier === "+";
            if (Array.isArray(value2)) {
                if (!repeat) {
                    throw new TypeError(`Expected "${token.name}" to not repeat, but got an array`);
                }
                if (value2.length === 0) {
                    if (optional) continue;
                    throw new TypeError(`Expected "${token.name}" to not be empty`);
                }
                for(let j = 0; j < value2.length; j++){
                    const segment = encode2(value2[j], token);
                    if (validate && !matches[i2].test(segment)) {
                        throw new TypeError(`Expected all "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                    }
                    path1 += token.prefix + segment + token.suffix;
                }
                continue;
            }
            if (typeof value2 === "string" || typeof value2 === "number") {
                const segment = encode2(String(value2), token);
                if (validate && !matches[i2].test(segment)) {
                    throw new TypeError(`Expected "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                }
                path1 += token.prefix + segment + token.suffix;
                continue;
            }
            if (optional) continue;
            const typeOfMessage = repeat ? "an array" : "a string";
            throw new TypeError(`Expected "${token.name}" to be ${typeOfMessage}`);
        }
        return path1;
    };
}
function escapeString(str1) {
    return str1.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
function flags(options2) {
    return options2 && options2.sensitive ? "" : "i";
}
function regexpToRegexp(path1, keys1) {
    if (!keys1) return path1;
    const groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
    let index = 0;
    let execResult = groupsRegex.exec(path1.source);
    while(execResult){
        keys1.push({
            name: execResult[1] || index++,
            prefix: "",
            suffix: "",
            modifier: "",
            pattern: ""
        });
        execResult = groupsRegex.exec(path1.source);
    }
    return path1;
}
function arrayToRegexp(paths, keys1, options2) {
    const parts = paths.map((path1)=>pathToRegexp(path1, keys1, options2).source
    );
    return new RegExp(`(?:${parts.join("|")})`, flags(options2));
}
function stringToRegexp(path1, keys1, options2) {
    return tokensToRegexp(parse3(path1, options2), keys1, options2);
}
function tokensToRegexp(tokens, keys1, options2 = {
}) {
    const { strict =false , start =true , end =true , encode: encode2 = (x)=>x
      } = options2;
    const endsWith = `[${escapeString(options2.endsWith || "")}]|$`;
    const delimiter3 = `[${escapeString(options2.delimiter || "/#?")}]`;
    let route = start ? "^" : "";
    for (const token of tokens){
        if (typeof token === "string") {
            route += escapeString(encode2(token));
        } else {
            const prefix = escapeString(encode2(token.prefix));
            const suffix = escapeString(encode2(token.suffix));
            if (token.pattern) {
                if (keys1) keys1.push(token);
                if (prefix || suffix) {
                    if (token.modifier === "+" || token.modifier === "*") {
                        const mod2 = token.modifier === "*" ? "?" : "";
                        route += `(?:${prefix}((?:${token.pattern})(?:${suffix}${prefix}(?:${token.pattern}))*)${suffix})${mod2}`;
                    } else {
                        route += `(?:${prefix}(${token.pattern})${suffix})${token.modifier}`;
                    }
                } else {
                    route += `(${token.pattern})${token.modifier}`;
                }
            } else {
                route += `(?:${prefix}${suffix})${token.modifier}`;
            }
        }
    }
    if (end) {
        if (!strict) route += `${delimiter3}?`;
        route += !options2.endsWith ? "$" : `(?=${endsWith})`;
    } else {
        const endToken = tokens[tokens.length - 1];
        const isEndDelimited = typeof endToken === "string" ? delimiter3.indexOf(endToken[endToken.length - 1]) > -1 : endToken === undefined;
        if (!strict) {
            route += `(?:${delimiter3}(?=${endsWith}))?`;
        }
        if (!isEndDelimited) {
            route += `(?=${delimiter3}|${endsWith})`;
        }
    }
    return new RegExp(route, flags(options2));
}
function pathToRegexp(path1, keys1, options2) {
    if (path1 instanceof RegExp) return regexpToRegexp(path1, keys1);
    if (Array.isArray(path1)) return arrayToRegexp(path1, keys1, options2);
    return stringToRegexp(path1, keys1, options2);
}
const errorStatusMap = {
    "BadRequest": 400,
    "Unauthorized": 401,
    "PaymentRequired": 402,
    "Forbidden": 403,
    "NotFound": 404,
    "MethodNotAllowed": 405,
    "NotAcceptable": 406,
    "ProxyAuthRequired": 407,
    "RequestTimeout": 408,
    "Conflict": 409,
    "Gone": 410,
    "LengthRequired": 411,
    "PreconditionFailed": 412,
    "RequestEntityTooLarge": 413,
    "RequestURITooLong": 414,
    "UnsupportedMediaType": 415,
    "RequestedRangeNotSatisfiable": 416,
    "ExpectationFailed": 417,
    "Teapot": 418,
    "MisdirectedRequest": 421,
    "UnprocessableEntity": 422,
    "Locked": 423,
    "FailedDependency": 424,
    "UpgradeRequired": 426,
    "PreconditionRequired": 428,
    "TooManyRequests": 429,
    "RequestHeaderFieldsTooLarge": 431,
    "UnavailableForLegalReasons": 451,
    "InternalServerError": 500,
    "NotImplemented": 501,
    "BadGateway": 502,
    "ServiceUnavailable": 503,
    "GatewayTimeout": 504,
    "HTTPVersionNotSupported": 505,
    "VariantAlsoNegotiates": 506,
    "InsufficientStorage": 507,
    "LoopDetected": 508,
    "NotExtended": 510,
    "NetworkAuthenticationRequired": 511
};
class HttpError extends Error {
    expose = false;
    status = Status.InternalServerError;
}
function createHttpErrorConstructor(status) {
    const name2 = `${Status[status]}Error`;
    const Ctor = class extends HttpError {
        constructor(message3){
            super();
            this.message = message3 || STATUS_TEXT.get(status);
            this.status = status;
            this.expose = status >= 400 && status < 500 ? true : false;
            Object.defineProperty(this, "name", {
                configurable: true,
                enumerable: false,
                value: name2,
                writable: true
            });
        }
    };
    return Ctor;
}
const httpErrors = {
};
for (const [key2, value2] of Object.entries(errorStatusMap)){
    httpErrors[key2] = createHttpErrorConstructor(value2);
}
function createHttpError(status = 500, message3) {
    return new httpErrors[Status[status]](message3);
}
const ENCODE_CHARS_REGEXP = /(?:[^\x21\x25\x26-\x3B\x3D\x3F-\x5B\x5D\x5F\x61-\x7A\x7E]|%(?:[^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|$))+/g;
const HTAB = "\t".charCodeAt(0);
const SPACE = " ".charCodeAt(0);
const CR1 = "\r".charCodeAt(0);
const LF1 = "\n".charCodeAt(0);
const UNMATCHED_SURROGATE_PAIR_REGEXP = /(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF]([^\uDC00-\uDFFF]|$)/g;
const UNMATCHED_SURROGATE_PAIR_REPLACE = "$1\uFFFD$2";
const BODY_TYPES = [
    "string",
    "number",
    "bigint",
    "boolean",
    "symbol"
];
function decodeComponent(text) {
    try {
        return decodeURIComponent(text);
    } catch  {
        return text;
    }
}
function encodeUrl(url) {
    return String(url).replace(UNMATCHED_SURROGATE_PAIR_REGEXP, UNMATCHED_SURROGATE_PAIR_REPLACE).replace(ENCODE_CHARS_REGEXP, encodeURI);
}
function getRandomFilename(prefix = "", extension1 = "") {
    return `${prefix}${createHash("sha1").update(crypto.getRandomValues(new Uint8Array(256))).toString("hex")}${extension1 ? `.${extension1}` : ""}`;
}
function getBoundary() {
    return `oak_${createHash("sha1").update(crypto.getRandomValues(new Uint8Array(256))).toString("hex")}`;
}
function isAsyncIterable(value3) {
    return typeof value3 === "object" && value3 !== null && Symbol.asyncIterator in value3 && typeof value3[Symbol.asyncIterator] === "function";
}
function isReader(value3) {
    return typeof value3 === "object" && value3 !== null && "read" in value3 && typeof value3.read === "function";
}
function isCloser(value3) {
    return typeof value3 === "object" && value3 != null && "close" in value3 && typeof value3["close"] === "function";
}
function isConn(value3) {
    return typeof value3 === "object" && value3 != null && "rid" in value3 && typeof value3.rid === "number" && "localAddr" in value3 && "remoteAddr" in value3;
}
function isListenTlsOptions(value3) {
    return typeof value3 === "object" && value3 !== null && "certFile" in value3 && "keyFile" in value3 && "port" in value3;
}
function readableStreamFromReader(reader1, options2 = {
}) {
    const { autoClose =true , chunkSize =16640 , strategy ,  } = options2;
    return new ReadableStream({
        async pull (controller) {
            const chunk = new Uint8Array(chunkSize);
            try {
                const read = await reader1.read(chunk);
                if (read === null) {
                    if (isCloser(reader1) && autoClose) {
                        reader1.close();
                    }
                    controller.close();
                    return;
                }
                controller.enqueue(chunk.subarray(0, read));
            } catch (e) {
                controller.error(e);
                if (isCloser(reader1)) {
                    reader1.close();
                }
            }
        },
        cancel () {
            if (isCloser(reader1) && autoClose) {
                reader1.close();
            }
        }
    }, strategy);
}
function isRedirectStatus(value3) {
    return [
        Status.MultipleChoices,
        Status.MovedPermanently,
        Status.Found,
        Status.SeeOther,
        Status.UseProxy,
        Status.TemporaryRedirect,
        Status.PermanentRedirect, 
    ].includes(value3);
}
function isHtml(value3) {
    return /^\s*<(?:!DOCTYPE|html|body)/i.test(value3);
}
function skipLWSPChar(u8) {
    const result = new Uint8Array(u8.length);
    let j = 0;
    for(let i2 = 0; i2 < u8.length; i2++){
        if (u8[i2] === SPACE || u8[i2] === HTAB) continue;
        result[j++] = u8[i2];
    }
    return result.slice(0, j);
}
function stripEol(value3) {
    if (value3[value3.byteLength - 1] == LF1) {
        let drop = 1;
        if (value3.byteLength > 1 && value3[value3.byteLength - 2] === CR1) {
            drop = 2;
        }
        return value3.subarray(0, value3.byteLength - drop);
    }
    return value3;
}
const UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
function resolvePath(rootPath, relativePath) {
    let path1 = relativePath;
    let root = rootPath;
    if (relativePath === undefined) {
        path1 = rootPath;
        root = ".";
    }
    if (path1 == null) {
        throw new TypeError("Argument relativePath is required.");
    }
    if (path1.includes("\0")) {
        throw createHttpError(400, "Malicious Path");
    }
    if (isAbsolute2(path1)) {
        throw createHttpError(400, "Malicious Path");
    }
    if (UP_PATH_REGEXP.test(normalize2("." + sep2 + path1))) {
        throw createHttpError(403);
    }
    return normalize2(join2(root, path1));
}
class Uint8ArrayTransformStream extends TransformStream {
    constructor(){
        const init = {
            async transform (chunk, controller) {
                chunk = await chunk;
                switch(typeof chunk){
                    case "object":
                        if (chunk === null) {
                            controller.terminate();
                        } else if (ArrayBuffer.isView(chunk)) {
                            controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
                        } else if (Array.isArray(chunk) && chunk.every((value3)=>typeof value3 === "number"
                        )) {
                            controller.enqueue(new Uint8Array(chunk));
                        } else if (typeof chunk.valueOf === "function" && chunk.valueOf() !== chunk) {
                            this.transform(chunk.valueOf(), controller);
                        } else if ("toJSON" in chunk) {
                            this.transform(JSON.stringify(chunk), controller);
                        }
                        break;
                    case "symbol":
                        controller.error(new TypeError("Cannot transform a symbol to a Uint8Array"));
                        break;
                    case "undefined":
                        controller.error(new TypeError("Cannot transform undefined to a Uint8Array"));
                        break;
                    default:
                        controller.enqueue(this.encoder.encode(String(chunk)));
                }
            },
            encoder: new TextEncoder()
        };
        super(init);
    }
}
const DomResponse = Response;
const serveHttp = "serveHttp" in Deno ? Deno.serveHttp.bind(Deno) : undefined;
const maybeUpgradeWebSocket = "upgradeWebSocket" in Deno ? Deno.upgradeWebSocket.bind(Deno) : undefined;
function hasNativeHttp() {
    return !!serveHttp;
}
class NativeRequest {
    #conn;
    #reject;
    #request;
    #requestPromise;
    #resolve;
    #resolved = false;
    #upgradeWebSocket;
    constructor(requestEvent, options2 = {
    }){
        const { conn: conn1  } = options2;
        this.#conn = conn1;
        this.#upgradeWebSocket = "upgradeWebSocket" in options2 ? options2["upgradeWebSocket"] : maybeUpgradeWebSocket;
        this.#request = requestEvent.request;
        const p1 = new Promise((resolve3, reject)=>{
            this.#resolve = resolve3;
            this.#reject = reject;
        });
        this.#requestPromise = requestEvent.respondWith(p1);
    }
    get body() {
        return this.#request.body;
    }
    get donePromise() {
        return this.#requestPromise;
    }
    get headers() {
        return this.#request.headers;
    }
    get method() {
        return this.#request.method;
    }
    get remoteAddr() {
        return this.#conn?.remoteAddr?.hostname;
    }
    get request() {
        return this.#request;
    }
    get url() {
        try {
            const url = new URL(this.#request.url);
            return this.#request.url.replace(url.origin, "");
        } catch  {
        }
        return this.#request.url;
    }
    get rawUrl() {
        return this.#request.url;
    }
    error(reason) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#reject(reason);
        this.#resolved = true;
    }
    respond(response) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#resolve(response);
        this.#resolved = true;
        return this.#requestPromise;
    }
    upgrade(options) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        if (!this.#upgradeWebSocket) {
            throw new TypeError("Upgrading web sockets not supported.");
        }
        const { response: response2 , websocket  } = this.#upgradeWebSocket(this.#request, options);
        this.#resolve(response2);
        this.#resolved = true;
        return websocket;
    }
}
class HttpServerNative {
    #app;
    #closed = false;
    #listener;
    #options;
    constructor(app1, options3){
        if (!("serveHttp" in Deno)) {
            throw new Error("The native bindings for serving HTTP are not available.");
        }
        this.#app = app1;
        this.#options = options3;
    }
    get app() {
        return this.#app;
    }
    get closed() {
        return this.#closed;
    }
    close() {
        this.#closed = true;
        if (this.#listener) {
            this.#listener.close();
            this.#listener = undefined;
        }
    }
    [Symbol.asyncIterator]() {
        const start = (controller)=>{
            const server = this;
            const listener1 = this.#listener = isListenTlsOptions(this.#options) ? Deno.listenTls(this.#options) : Deno.listen(this.#options);
            async function serve1(conn2) {
                const httpConn = serveHttp(conn2);
                while(true){
                    try {
                        const requestEvent1 = await httpConn.nextRequest();
                        if (requestEvent1 === null) {
                            return;
                        }
                        const nativeRequest = new NativeRequest(requestEvent1, {
                            conn: conn2
                        });
                        controller.enqueue(nativeRequest);
                        await nativeRequest.donePromise;
                    } catch (error) {
                        server.app.dispatchEvent(new ErrorEvent("error", {
                            error
                        }));
                    }
                    if (server.closed) {
                        httpConn.close();
                        controller.close();
                    }
                }
            }
            async function accept() {
                while(true){
                    try {
                        const conn2 = await listener1.accept();
                        serve1(conn2);
                    } catch (error) {
                        if (!server.closed) {
                            server.app.dispatchEvent(new ErrorEvent("error", {
                                error
                            }));
                        }
                    }
                    if (server.closed) {
                        controller.close();
                        return;
                    }
                }
            }
            accept();
        };
        const stream = new ReadableStream({
            start
        });
        return stream[Symbol.asyncIterator]();
    }
}
const SUBTYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.-]{0,126}$/;
const TYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126}$/;
const TYPE_REGEXP = /^ *([A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126})\/([A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}) *$/;
class MediaType {
    type;
    subtype;
    suffix;
    constructor(type1, subtype, suffix){
        this.type = type1;
        this.subtype = subtype;
        this.suffix = suffix;
    }
}
function format3(obj) {
    const { subtype: subtype1 , suffix: suffix1 , type: type1  } = obj;
    if (!TYPE_NAME_REGEXP.test(type1)) {
        throw new TypeError("Invalid type.");
    }
    if (!SUBTYPE_NAME_REGEXP.test(subtype1)) {
        throw new TypeError("Invalid subtype.");
    }
    let str1 = `${type1}/${subtype1}`;
    if (suffix1) {
        if (!TYPE_NAME_REGEXP.test(suffix1)) {
            throw new TypeError("Invalid suffix.");
        }
        str1 += `+${suffix1}`;
    }
    return str1;
}
function parse4(str1) {
    const match = TYPE_REGEXP.exec(str1.toLowerCase());
    if (!match) {
        throw new TypeError("Invalid media type.");
    }
    let [, type1, subtype1] = match;
    let suffix1;
    const idx = subtype1.lastIndexOf("+");
    if (idx !== -1) {
        suffix1 = subtype1.substr(idx + 1);
        subtype1 = subtype1.substr(0, idx);
    }
    return new MediaType(type1, subtype1, suffix1);
}
function mimeMatch(expected, actual) {
    if (expected === undefined) {
        return false;
    }
    const actualParts = actual.split("/");
    const expectedParts = expected.split("/");
    if (actualParts.length !== 2 || expectedParts.length !== 2) {
        return false;
    }
    const [actualType, actualSubtype] = actualParts;
    const [expectedType, expectedSubtype] = expectedParts;
    if (expectedType !== "*" && expectedType !== actualType) {
        return false;
    }
    if (expectedSubtype.substr(0, 2) === "*+") {
        return expectedSubtype.length <= actualSubtype.length + 1 && expectedSubtype.substr(1) === actualSubtype.substr(1 - expectedSubtype.length);
    }
    if (expectedSubtype !== "*" && expectedSubtype !== actualSubtype) {
        return false;
    }
    return true;
}
function normalize3(type1) {
    if (type1 === "urlencoded") {
        return "application/x-www-form-urlencoded";
    } else if (type1 === "multipart") {
        return "multipart/*";
    } else if (type1[0] === "+") {
        return `*/*${type1}`;
    }
    return type1.includes("/") ? type1 : lookup(type1);
}
function normalizeType(value3) {
    try {
        const val = value3.split(";");
        const type1 = parse4(val[0]);
        return format3(type1);
    } catch  {
        return;
    }
}
function isMediaType(value3, types1) {
    const val = normalizeType(value3);
    if (!val) {
        return false;
    }
    if (!types1.length) {
        return val;
    }
    for (const type1 of types1){
        if (mimeMatch(normalize3(type1), val)) {
            return type1[0] === "+" || type1.includes("*") ? val : type1;
        }
    }
    return false;
}
const MIN_BUF_SIZE1 = 16;
const CR2 = "\r".charCodeAt(0);
const LF2 = "\n".charCodeAt(0);
class BufferFullError1 extends Error {
    partial;
    name = "BufferFullError";
    constructor(partial2){
        super("Buffer full");
        this.partial = partial2;
    }
}
class BufReader1 {
    #buffer;
    #reader;
    #posRead = 0;
    #posWrite = 0;
    #eof = false;
    async #fill() {
        if (this.#posRead > 0) {
            this.#buffer.copyWithin(0, this.#posRead, this.#posWrite);
            this.#posWrite -= this.#posRead;
            this.#posRead = 0;
        }
        if (this.#posWrite >= this.#buffer.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i2 = 100; i2 > 0; i2--){
            const rr = await this.#reader.read(this.#buffer.subarray(this.#posWrite));
            if (rr === null) {
                this.#eof = true;
                return;
            }
            assert1(rr >= 0, "negative read");
            this.#posWrite += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    }
     #reset(buffer, reader) {
        this.#buffer = buffer;
        this.#reader = reader;
        this.#eof = false;
    }
    constructor(rd2, size4 = 4096){
        if (size4 < 16) {
            size4 = MIN_BUF_SIZE1;
        }
        this.#reset(new Uint8Array(size4), rd2);
    }
    buffered() {
        return this.#posWrite - this.#posRead;
    }
    async readLine(strip = true) {
        let line;
        try {
            line = await this.readSlice(LF2);
        } catch (err) {
            let { partial: partial3  } = err;
            assert1(partial3 instanceof Uint8Array, "Caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError1)) {
                throw err;
            }
            if (!this.#eof && partial3.byteLength > 0 && partial3[partial3.byteLength - 1] === CR2) {
                assert1(this.#posRead > 0, "Tried to rewind past start of buffer");
                this.#posRead--;
                partial3 = partial3.subarray(0, partial3.byteLength - 1);
            }
            return {
                bytes: partial3,
                eol: this.#eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                bytes: line,
                eol: true
            };
        }
        if (strip) {
            line = stripEol(line);
        }
        return {
            bytes: line,
            eol: true
        };
    }
    async readSlice(delim) {
        let s1 = 0;
        let slice;
        while(true){
            let i2 = this.#buffer.subarray(this.#posRead + s1, this.#posWrite).indexOf(delim);
            if (i2 >= 0) {
                i2 += s1;
                slice = this.#buffer.subarray(this.#posRead, this.#posRead + i2 + 1);
                this.#posRead += i2 + 1;
                break;
            }
            if (this.#eof) {
                if (this.#posRead === this.#posWrite) {
                    return null;
                }
                slice = this.#buffer.subarray(this.#posRead, this.#posWrite);
                this.#posRead = this.#posWrite;
                break;
            }
            if (this.buffered() >= this.#buffer.byteLength) {
                this.#posRead = this.#posWrite;
                const oldbuf = this.#buffer;
                const newbuf = this.#buffer.slice(0);
                this.#buffer = newbuf;
                throw new BufferFullError1(oldbuf);
            }
            s1 = this.#posWrite - this.#posRead;
            try {
                await this.#fill();
            } catch (err) {
                err.partial = slice;
                throw err;
            }
        }
        return slice;
    }
}
const COLON = ":".charCodeAt(0);
const HTAB1 = "\t".charCodeAt(0);
const SPACE1 = " ".charCodeAt(0);
const decoder1 = new TextDecoder();
function toParamRegExp(attributePattern, flags1) {
    return new RegExp(`(?:^|;)\\s*${attributePattern}\\s*=\\s*` + `(` + `[^";\\s][^;\\s]*` + `|` + `"(?:[^"\\\\]|\\\\"?)+"?` + `)`, flags1);
}
async function readHeaders(body) {
    const headers = {
    };
    let readResult = await body.readLine();
    while(readResult){
        const { bytes  } = readResult;
        if (!bytes.length) {
            return headers;
        }
        let i2 = bytes.indexOf(COLON);
        if (i2 === -1) {
            throw new httpErrors.BadRequest(`Malformed header: ${decoder1.decode(bytes)}`);
        }
        const key3 = decoder1.decode(bytes.subarray(0, i2)).trim().toLowerCase();
        if (key3 === "") {
            throw new httpErrors.BadRequest("Invalid header key.");
        }
        i2++;
        while(i2 < bytes.byteLength && (bytes[i2] === SPACE1 || bytes[i2] === HTAB1)){
            i2++;
        }
        const value3 = decoder1.decode(bytes.subarray(i2)).trim();
        headers[key3] = value3;
        readResult = await body.readLine();
    }
    throw new httpErrors.BadRequest("Unexpected end of body reached.");
}
function unquote(value3) {
    if (value3.startsWith(`"`)) {
        const parts = value3.slice(1).split(`\\"`);
        for(let i2 = 0; i2 < parts.length; ++i2){
            const quoteIndex = parts[i2].indexOf(`"`);
            if (quoteIndex !== -1) {
                parts[i2] = parts[i2].slice(0, quoteIndex);
                parts.length = i2 + 1;
            }
            parts[i2] = parts[i2].replace(/\\(.)/g, "$1");
        }
        value3 = parts.join(`"`);
    }
    return value3;
}
let needsEncodingFixup = false;
function fixupEncoding(value3) {
    if (needsEncodingFixup && /[\x80-\xff]/.test(value3)) {
        value3 = textDecode("utf-8", value3);
        if (needsEncodingFixup) {
            value3 = textDecode("iso-8859-1", value3);
        }
    }
    return value3;
}
const FILENAME_STAR_REGEX = toParamRegExp("filename\\*", "i");
const FILENAME_START_ITER_REGEX = toParamRegExp("filename\\*((?!0\\d)\\d+)(\\*?)", "ig");
const FILENAME_REGEX = toParamRegExp("filename", "i");
function rfc2047decode(value3) {
    if (!value3.startsWith("=?") || /[\x00-\x19\x80-\xff]/.test(value3)) {
        return value3;
    }
    return value3.replace(/=\?([\w-]*)\?([QqBb])\?((?:[^?]|\?(?!=))*)\?=/g, (_, charset1, encoding, text)=>{
        if (encoding === "q" || encoding === "Q") {
            text = text.replace(/_/g, " ");
            text = text.replace(/=([0-9a-fA-F]{2})/g, (_1, hex)=>String.fromCharCode(parseInt(hex, 16))
            );
            return textDecode(charset1, text);
        }
        try {
            text = atob(text);
        } catch  {
        }
        return textDecode(charset1, text);
    });
}
function rfc2231getParam(header) {
    const matches = [];
    let match;
    while(match = FILENAME_START_ITER_REGEX.exec(header)){
        const [, ns, quote, part] = match;
        const n = parseInt(ns, 10);
        if (n in matches) {
            if (n === 0) {
                break;
            }
            continue;
        }
        matches[n] = [
            quote,
            part
        ];
    }
    const parts = [];
    for(let n = 0; n < matches.length; ++n){
        if (!(n in matches)) {
            break;
        }
        let [quote, part] = matches[n];
        part = unquote(part);
        if (quote) {
            part = unescape(part);
            if (n === 0) {
                part = rfc5987decode(part);
            }
        }
        parts.push(part);
    }
    return parts.join("");
}
function rfc5987decode(value3) {
    const encodingEnd = value3.indexOf(`'`);
    if (encodingEnd === -1) {
        return value3;
    }
    const encoding = value3.slice(0, encodingEnd);
    const langValue = value3.slice(encodingEnd + 1);
    return textDecode(encoding, langValue.replace(/^[^']*'/, ""));
}
function textDecode(encoding, value3) {
    if (encoding) {
        try {
            const decoder2 = new TextDecoder(encoding, {
                fatal: true
            });
            const bytes = Array.from(value3, (c)=>c.charCodeAt(0)
            );
            if (bytes.every((code)=>code <= 255
            )) {
                value3 = decoder2.decode(new Uint8Array(bytes));
                needsEncodingFixup = false;
            }
        } catch  {
        }
    }
    return value3;
}
function getFilename(header) {
    needsEncodingFixup = true;
    let matches = FILENAME_STAR_REGEX.exec(header);
    if (matches) {
        const [, filename] = matches;
        return fixupEncoding(rfc2047decode(rfc5987decode(unescape(unquote(filename)))));
    }
    const filename = rfc2231getParam(header);
    if (filename) {
        return fixupEncoding(rfc2047decode(filename));
    }
    matches = FILENAME_REGEX.exec(header);
    if (matches) {
        const [, filename1] = matches;
        return fixupEncoding(rfc2047decode(unquote(filename1)));
    }
    return "";
}
const decoder2 = new TextDecoder();
const encoder1 = new TextEncoder();
const BOUNDARY_PARAM_REGEX = toParamRegExp("boundary", "i");
const NAME_PARAM_REGEX = toParamRegExp("name", "i");
function append(a, b) {
    const ab1 = new Uint8Array(a.length + b.length);
    ab1.set(a, 0);
    ab1.set(b, a.length);
    return ab1;
}
function isEqual(a, b) {
    return equals(skipLWSPChar(a), b);
}
async function readToStartOrEnd(body, start, end) {
    let lineResult;
    while(lineResult = await body.readLine()){
        if (isEqual(lineResult.bytes, start)) {
            return true;
        }
        if (isEqual(lineResult.bytes, end)) {
            return false;
        }
    }
    throw new httpErrors.BadRequest("Unable to find multi-part boundary.");
}
async function* parts({ body , final: __final , part , maxFileSize , maxSize , outPath , prefix  }) {
    async function getFile(contentType1) {
        const ext = extension(contentType1);
        if (!ext) {
            throw new httpErrors.BadRequest(`Invalid media type for part: ${ext}`);
        }
        if (!outPath) {
            outPath = await Deno.makeTempDir();
        }
        const filename = `${outPath}/${getRandomFilename(prefix, ext)}`;
        const file = await Deno.open(filename, {
            write: true,
            createNew: true
        });
        return [
            filename,
            file
        ];
    }
    while(true){
        const headers = await readHeaders(body);
        const contentType1 = headers["content-type"];
        const contentDisposition = headers["content-disposition"];
        if (!contentDisposition) {
            throw new httpErrors.BadRequest("Form data part missing content-disposition header");
        }
        if (!contentDisposition.match(/^form-data;/i)) {
            throw new httpErrors.BadRequest(`Unexpected content-disposition header: "${contentDisposition}"`);
        }
        const matches = NAME_PARAM_REGEX.exec(contentDisposition);
        if (!matches) {
            throw new httpErrors.BadRequest(`Unable to determine name of form body part`);
        }
        let [, name2] = matches;
        name2 = unquote(name2);
        if (contentType1) {
            const originalName = getFilename(contentDisposition);
            let byteLength = 0;
            let file;
            let filename;
            let buf;
            if (maxSize) {
                buf = new Uint8Array();
            } else {
                const result = await getFile(contentType1);
                filename = result[0];
                file = result[1];
            }
            while(true){
                const readResult = await body.readLine(false);
                if (!readResult) {
                    throw new httpErrors.BadRequest("Unexpected EOF reached");
                }
                const { bytes  } = readResult;
                const strippedBytes = stripEol(bytes);
                if (isEqual(strippedBytes, part) || isEqual(strippedBytes, __final)) {
                    if (file) {
                        const bytesDiff = bytes.length - strippedBytes.length;
                        if (bytesDiff) {
                            const originalBytesSize = await file.seek(-bytesDiff, Deno.SeekMode.Current);
                            await file.truncate(originalBytesSize);
                        }
                        file.close();
                    }
                    yield [
                        name2,
                        {
                            content: buf,
                            contentType: contentType1,
                            name: name2,
                            filename,
                            originalName
                        }, 
                    ];
                    if (isEqual(strippedBytes, __final)) {
                        return;
                    }
                    break;
                }
                byteLength += bytes.byteLength;
                if (byteLength > maxFileSize) {
                    if (file) {
                        file.close();
                    }
                    throw new httpErrors.RequestEntityTooLarge(`File size exceeds limit of ${maxFileSize} bytes.`);
                }
                if (buf) {
                    if (byteLength > maxSize) {
                        const result = await getFile(contentType1);
                        filename = result[0];
                        file = result[1];
                        await writeAll(file, buf);
                        buf = undefined;
                    } else {
                        buf = append(buf, bytes);
                    }
                }
                if (file) {
                    await writeAll(file, bytes);
                }
            }
        } else {
            const lines = [];
            while(true){
                const readResult = await body.readLine();
                if (!readResult) {
                    throw new httpErrors.BadRequest("Unexpected EOF reached");
                }
                const { bytes  } = readResult;
                if (isEqual(bytes, part) || isEqual(bytes, __final)) {
                    yield [
                        name2,
                        lines.join("\n")
                    ];
                    if (isEqual(bytes, __final)) {
                        return;
                    }
                    break;
                }
                lines.push(decoder2.decode(bytes));
            }
        }
    }
}
class FormDataReader {
    #body;
    #boundaryFinal;
    #boundaryPart;
    #reading = false;
    constructor(contentType1, body){
        const matches = contentType1.match(BOUNDARY_PARAM_REGEX);
        if (!matches) {
            throw new httpErrors.BadRequest(`Content type "${contentType1}" does not contain a valid boundary.`);
        }
        let [, boundary] = matches;
        boundary = unquote(boundary);
        this.#boundaryPart = encoder1.encode(`--${boundary}`);
        this.#boundaryFinal = encoder1.encode(`--${boundary}--`);
        this.#body = body;
    }
    async read(options = {
    }) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath , maxFileSize =10485760 , maxSize =0 , bufferSize =1048576 ,  } = options;
        const body1 = new BufReader1(this.#body, bufferSize);
        const result = {
            fields: {
            }
        };
        if (!await readToStartOrEnd(body1, this.#boundaryPart, this.#boundaryFinal)) {
            return result;
        }
        try {
            for await (const part of parts({
                body: body1,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                const [key3, value3] = part;
                if (typeof value3 === "string") {
                    result.fields[key3] = value3;
                } else {
                    if (!result.files) {
                        result.files = [];
                    }
                    result.files.push(value3);
                }
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
        return result;
    }
    async *stream(options = {
    }) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath , maxFileSize =10485760 , maxSize =0 , bufferSize =32000 ,  } = options;
        const body1 = new BufReader1(this.#body, bufferSize);
        if (!await readToStartOrEnd(body1, this.#boundaryPart, this.#boundaryFinal)) {
            return;
        }
        try {
            for await (const part of parts({
                body: body1,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                yield part;
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
        })}`;
    }
}
const defaultBodyContentTypes = {
    json: [
        "json",
        "application/*+json",
        "application/csp-report"
    ],
    form: [
        "urlencoded"
    ],
    formData: [
        "multipart"
    ],
    text: [
        "text"
    ]
};
function resolveType(contentType2, contentTypes) {
    const contentTypesJson = [
        ...defaultBodyContentTypes.json,
        ...contentTypes.json ?? [], 
    ];
    const contentTypesForm = [
        ...defaultBodyContentTypes.form,
        ...contentTypes.form ?? [], 
    ];
    const contentTypesFormData = [
        ...defaultBodyContentTypes.formData,
        ...contentTypes.formData ?? [], 
    ];
    const contentTypesText = [
        ...defaultBodyContentTypes.text,
        ...contentTypes.text ?? [], 
    ];
    if (contentTypes.bytes && isMediaType(contentType2, contentTypes.bytes)) {
        return "bytes";
    } else if (isMediaType(contentType2, contentTypesJson)) {
        return "json";
    } else if (isMediaType(contentType2, contentTypesForm)) {
        return "form";
    } else if (isMediaType(contentType2, contentTypesFormData)) {
        return "form-data";
    } else if (isMediaType(contentType2, contentTypesText)) {
        return "text";
    }
    return "bytes";
}
const decoder3 = new TextDecoder();
function bodyAsReader(body1) {
    return body1 instanceof ReadableStream ? readerFromStreamReader(body1.getReader()) : body1 ?? new Buffer();
}
function bodyAsStream(body1) {
    return body1 instanceof ReadableStream ? body1 : readableStreamFromReader(body1);
}
class RequestBody {
    #formDataReader;
    #has;
    #readAllBody;
    #request;
    #type;
     #parse(type) {
        switch(type){
            case "form":
                this.#type = "bytes";
                return async ()=>new URLSearchParams(decoder3.decode(await this.#valuePromise()).replace(/\+/g, " "))
                ;
            case "form-data":
                this.#type = "form-data";
                return ()=>{
                    const contentType2 = this.#request.headers.get("content-type");
                    assert1(contentType2);
                    return this.#formDataReader ?? (this.#formDataReader = new FormDataReader(contentType2, bodyAsReader(this.#request.body)));
                };
            case "json":
                this.#type = "bytes";
                return async ()=>JSON.parse(decoder3.decode(await this.#valuePromise()))
                ;
            case "bytes":
                this.#type = "bytes";
                return ()=>this.#valuePromise()
                ;
            case "text":
                this.#type = "bytes";
                return async ()=>decoder3.decode(await this.#valuePromise())
                ;
            default:
                throw new TypeError(`Invalid body type: "${type}"`);
        }
    }
     #validateGetArgs(type, contentTypes) {
        if (type === "reader" && this.#type && this.#type !== "reader") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a reader.`);
        }
        if (type === "stream" && this.#type && this.#type !== "stream") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (type === "form-data" && this.#type && this.#type !== "form-data") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (this.#type === "reader" && type !== "reader") {
            throw new TypeError("Body already consumed as a reader and can only be returned as a reader.");
        }
        if (this.#type === "stream" && type !== "stream") {
            throw new TypeError("Body already consumed as a stream and can only be returned as a stream.");
        }
        if (this.#type === "form-data" && type !== "form-data") {
            throw new TypeError("Body already consumed as form data and can only be returned as form data.");
        }
        if (type && Object.keys(contentTypes).length) {
            throw new TypeError(`"type" and "contentTypes" cannot be specified at the same time`);
        }
    }
     #valuePromise() {
        return this.#readAllBody ?? (this.#readAllBody = this.#request instanceof Request ? this.#request.arrayBuffer().then((ab1)=>new Uint8Array(ab1)
        ) : readAll(this.#request.body));
    }
    constructor(request1){
        this.#request = request1;
    }
    get({ type , contentTypes ={
    }  }) {
        this.#validateGetArgs(type, contentTypes);
        if (type === "reader") {
            this.#type = "reader";
            return {
                type,
                value: bodyAsReader(this.#request.body)
            };
        }
        if (type === "stream") {
            if (!this.#request.body) {
                this.#type = "undefined";
                throw new TypeError(`Body is undefined and cannot be returned as "stream".`);
            }
            this.#type = "stream";
            return {
                type,
                value: bodyAsStream(this.#request.body)
            };
        }
        if (!this.has()) {
            this.#type = "undefined";
        } else if (!this.#type) {
            const encoding = this.#request.headers.get("content-encoding") ?? "identity";
            if (encoding !== "identity") {
                throw new httpErrors.UnsupportedMediaType(`Unsupported content-encoding: ${encoding}`);
            }
        }
        if (this.#type === "undefined") {
            if (type && type !== "undefined") {
                throw new TypeError(`Body is undefined and cannot be returned as "${type}".`);
            }
            return {
                type: "undefined",
                value: undefined
            };
        }
        if (!type) {
            const contentType2 = this.#request.headers.get("content-type");
            assert1(contentType2, "The Content-Type header is missing from the request");
            type = resolveType(contentType2, contentTypes);
        }
        assert1(type);
        const body1 = Object.create(null);
        Object.defineProperties(body1, {
            type: {
                value: type,
                configurable: true,
                enumerable: true
            },
            value: {
                get: this.#parse(type),
                configurable: true,
                enumerable: true
            }
        });
        return body1;
    }
    has() {
        return this.#has !== undefined ? this.#has : this.#has = this.#request.body != null && (this.#request.headers.has("transfer-encoding") || !!parseInt(this.#request.headers.get("content-length") ?? "", 10)) || this.#request.body instanceof ReadableStream;
    }
}
function compareSpecs(a, b) {
    return b.q - a.q || (b.s ?? 0) - (a.s ?? 0) || (a.o ?? 0) - (b.o ?? 0) || a.i - b.i || 0;
}
function isQuality(spec) {
    return spec.q > 0;
}
const SIMPLE_CHARSET_REGEXP = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
function parseCharset(str1, i2) {
    const match = SIMPLE_CHARSET_REGEXP.exec(str1);
    if (!match) {
        return;
    }
    const [, charset1] = match;
    let q = 1;
    if (match[2]) {
        const params = match[2].split(";");
        for (const param of params){
            const [key3, value3] = param.trim().split("=");
            if (key3 === "q") {
                q = parseFloat(value3);
                break;
            }
        }
    }
    return {
        charset: charset1,
        q,
        i: i2
    };
}
function parseAcceptCharset(accept) {
    const accepts = accept.split(",");
    const result = [];
    for(let i2 = 0; i2 < accepts.length; i2++){
        const charset1 = parseCharset(accepts[i2].trim(), i2);
        if (charset1) {
            result.push(charset1);
        }
    }
    return result;
}
function specify(charset1, spec, i2) {
    let s1 = 0;
    if (spec.charset.toLowerCase() === charset1.toLocaleLowerCase()) {
        s1 |= 1;
    } else if (spec.charset !== "*") {
        return;
    }
    return {
        i: i2,
        o: spec.i,
        q: spec.q,
        s: s1
    };
}
function getCharsetPriority(charset1, accepted, index) {
    let priority = {
        i: -1,
        o: -1,
        q: 0,
        s: 0
    };
    for (const accepts of accepted){
        const spec = specify(charset1, accepts, index);
        if (spec && ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q || (priority.o ?? 0) - (spec.o ?? 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredCharsets(accept = "*", provided) {
    const accepts = parseAcceptCharset(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.charset
        );
    }
    const priorities = provided.map((type2, index)=>getCharsetPriority(type2, accepts, index)
    );
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
const simpleEncodingRegExp = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
function parseEncoding(str1, i2) {
    const match = simpleEncodingRegExp.exec(str1);
    if (!match) {
        return undefined;
    }
    const encoding = match[1];
    let q = 1;
    if (match[2]) {
        const params = match[2].split(";");
        for (const param of params){
            const p1 = param.trim().split("=");
            if (p1[0] === "q") {
                q = parseFloat(p1[1]);
                break;
            }
        }
    }
    return {
        encoding,
        q,
        i: i2
    };
}
function specify1(encoding, spec, i2 = -1) {
    if (!spec.encoding) {
        return;
    }
    let s1 = 0;
    if (spec.encoding.toLocaleLowerCase() === encoding.toLocaleLowerCase()) {
        s1 = 1;
    } else if (spec.encoding !== "*") {
        return;
    }
    return {
        i: i2,
        o: spec.i,
        q: spec.q,
        s: s1
    };
}
function parseAcceptEncoding(accept) {
    const accepts = accept.split(",");
    const parsedAccepts = [];
    let hasIdentity = false;
    let minQuality = 1;
    for(let i2 = 0; i2 < accepts.length; i2++){
        const encoding = parseEncoding(accepts[i2].trim(), i2);
        if (encoding) {
            parsedAccepts.push(encoding);
            hasIdentity = hasIdentity || !!specify1("identity", encoding);
            minQuality = Math.min(minQuality, encoding.q || 1);
        }
    }
    if (!hasIdentity) {
        parsedAccepts.push({
            encoding: "identity",
            q: minQuality,
            i: accepts.length - 1
        });
    }
    return parsedAccepts;
}
function getEncodingPriority(encoding, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: 0
    };
    for (const s1 of accepted){
        const spec = specify1(encoding, s1, index);
        if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredEncodings(accept, provided) {
    const accepts = parseAcceptEncoding(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.encoding
        );
    }
    const priorities = provided.map((type2, index)=>getEncodingPriority(type2, accepts, index)
    );
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
const SIMPLE_LANGUAGE_REGEXP = /^\s*([^\s\-;]+)(?:-([^\s;]+))?\s*(?:;(.*))?$/;
function parseLanguage(str1, i2) {
    const match = SIMPLE_LANGUAGE_REGEXP.exec(str1);
    if (!match) {
        return undefined;
    }
    const [, prefix, suffix1] = match;
    const full = suffix1 ? `${prefix}-${suffix1}` : prefix;
    let q = 1;
    if (match[3]) {
        const params = match[3].split(";");
        for (const param of params){
            const [key3, value3] = param.trim().split("=");
            if (key3 === "q") {
                q = parseFloat(value3);
                break;
            }
        }
    }
    return {
        prefix,
        suffix: suffix1,
        full,
        q,
        i: i2
    };
}
function parseAcceptLanguage(accept) {
    const accepts = accept.split(",");
    const result = [];
    for(let i2 = 0; i2 < accepts.length; i2++){
        const language = parseLanguage(accepts[i2].trim(), i2);
        if (language) {
            result.push(language);
        }
    }
    return result;
}
function specify2(language, spec, i2) {
    const p1 = parseLanguage(language, i2);
    if (!p1) {
        return undefined;
    }
    let s1 = 0;
    if (spec.full.toLowerCase() === p1.full.toLowerCase()) {
        s1 |= 4;
    } else if (spec.prefix.toLowerCase() === p1.prefix.toLowerCase()) {
        s1 |= 2;
    } else if (spec.full.toLowerCase() === p1.prefix.toLowerCase()) {
        s1 |= 1;
    } else if (spec.full !== "*") {
        return;
    }
    return {
        i: i2,
        o: spec.i,
        q: spec.q,
        s: s1
    };
}
function getLanguagePriority(language, accepted, index) {
    let priority = {
        i: -1,
        o: -1,
        q: 0,
        s: 0
    };
    for (const accepts of accepted){
        const spec = specify2(language, accepts, index);
        if (spec && ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q || (priority.o ?? 0) - (spec.o ?? 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredLanguages(accept = "*", provided) {
    const accepts = parseAcceptLanguage(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.full
        );
    }
    const priorities = provided.map((type2, index)=>getLanguagePriority(type2, accepts, index)
    );
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
const simpleMediaTypeRegExp = /^\s*([^\s\/;]+)\/([^;\s]+)\s*(?:;(.*))?$/;
function quoteCount(str1) {
    let count = 0;
    let index = 0;
    while((index = str1.indexOf(`"`, index)) !== -1){
        count++;
        index++;
    }
    return count;
}
function splitMediaTypes(accept) {
    const accepts = accept.split(",");
    let j = 0;
    for(let i2 = 1; i2 < accepts.length; i2++){
        if (quoteCount(accepts[j]) % 2 === 0) {
            accepts[++j] = accepts[i2];
        } else {
            accepts[j] += `,${accepts[i2]}`;
        }
    }
    accepts.length = j + 1;
    return accepts;
}
function splitParameters(str1) {
    const parameters = str1.split(";");
    let j = 0;
    for(let i2 = 1; i2 < parameters.length; i2++){
        if (quoteCount(parameters[j]) % 2 === 0) {
            parameters[++j] = parameters[i2];
        } else {
            parameters[j] += `;${parameters[i2]}`;
        }
    }
    parameters.length = j + 1;
    return parameters.map((p1)=>p1.trim()
    );
}
function splitKeyValuePair(str1) {
    const [key3, value3] = str1.split("=");
    return [
        key3.toLowerCase(),
        value3
    ];
}
function parseMediaType(str1, i2) {
    const match = simpleMediaTypeRegExp.exec(str1);
    if (!match) {
        return;
    }
    const params = Object.create(null);
    let q = 1;
    const [, type2, subtype1, parameters] = match;
    if (parameters) {
        const kvps = splitParameters(parameters).map(splitKeyValuePair);
        for (const [key3, val] of kvps){
            const value3 = val && val[0] === `"` && val[val.length - 1] === `"` ? val.substr(1, val.length - 2) : val;
            if (key3 === "q" && value3) {
                q = parseFloat(value3);
                break;
            }
            params[key3] = value3;
        }
    }
    return {
        type: type2,
        subtype: subtype1,
        params,
        q,
        i: i2
    };
}
function parseAccept(accept) {
    const accepts = splitMediaTypes(accept);
    const mediaTypes = [];
    for(let i2 = 0; i2 < accepts.length; i2++){
        const mediaType = parseMediaType(accepts[i2].trim(), i2);
        if (mediaType) {
            mediaTypes.push(mediaType);
        }
    }
    return mediaTypes;
}
function getFullType(spec) {
    return `${spec.type}/${spec.subtype}`;
}
function specify3(type2, spec, index) {
    const p1 = parseMediaType(type2, index);
    if (!p1) {
        return;
    }
    let s1 = 0;
    if (spec.type.toLowerCase() === p1.type.toLowerCase()) {
        s1 |= 4;
    } else if (spec.type !== "*") {
        return;
    }
    if (spec.subtype.toLowerCase() === p1.subtype.toLowerCase()) {
        s1 |= 2;
    } else if (spec.subtype !== "*") {
        return;
    }
    const keys1 = Object.keys(spec.params);
    if (keys1.length) {
        if (keys1.every((key3)=>(spec.params[key3] || "").toLowerCase() === (p1.params[key3] || "").toLowerCase()
        )) {
            s1 |= 1;
        } else {
            return;
        }
    }
    return {
        i: index,
        o: spec.o,
        q: spec.q,
        s: s1
    };
}
function getMediaTypePriority(type2, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: index
    };
    for (const accepts of accepted){
        const spec = specify3(type2, accepts, index);
        if (spec && ((priority.s || 0) - (spec.s || 0) || (priority.q || 0) - (spec.q || 0) || (priority.o || 0) - (spec.o || 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredMediaTypes(accept, provided) {
    const accepts = parseAccept(accept === undefined ? "*/*" : accept || "");
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map(getFullType);
    }
    const priorities = provided.map((type2, index)=>{
        return getMediaTypePriority(type2, accepts, index);
    });
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
class Request1 {
    #body;
    #proxy;
    #secure;
    #serverRequest;
    #url;
     #getRemoteAddr() {
        return this.#serverRequest instanceof NativeRequest ? this.#serverRequest.remoteAddr ?? "" : this.#serverRequest?.conn?.remoteAddr?.hostname ?? "";
    }
    get hasBody() {
        return this.#body.has();
    }
    get headers() {
        return this.#serverRequest.headers;
    }
    get ip() {
        return (this.#proxy ? this.ips[0] : this.#getRemoteAddr()) ?? "";
    }
    get ips() {
        return this.#proxy ? (this.#serverRequest.headers.get("x-forwarded-for") ?? this.#getRemoteAddr()).split(/\s*,\s*/) : [];
    }
    get method() {
        return this.#serverRequest.method;
    }
    get secure() {
        return this.#secure;
    }
    get originalRequest() {
        return this.#serverRequest;
    }
    get url() {
        if (!this.#url) {
            const serverRequest = this.#serverRequest;
            if (serverRequest instanceof NativeRequest && !this.#proxy) {
                try {
                    this.#url = new URL(serverRequest.rawUrl);
                    return this.#url;
                } catch  {
                }
            }
            let proto;
            let host;
            if (this.#proxy) {
                proto = serverRequest.headers.get("x-forwarded-proto")?.split(/\s*,\s*/, 1)[0] ?? "http";
                host = (serverRequest.headers.get("x-forwarded-host") ?? serverRequest.headers.get("host")) ?? "";
            } else {
                proto = this.#secure ? "https" : "http";
                host = serverRequest.headers.get("host") ?? "";
            }
            try {
                this.#url = new URL(`${proto}://${host}${serverRequest.url}`);
            } catch  {
                throw new TypeError(`The server request URL of "${proto}://${host}${serverRequest.url}" is invalid.`);
            }
        }
        return this.#url;
    }
    constructor(serverRequest, proxy1 = false, secure1 = false){
        this.#proxy = proxy1;
        this.#secure = secure1;
        this.#serverRequest = serverRequest;
        this.#body = new RequestBody(serverRequest instanceof NativeRequest ? serverRequest.request : serverRequest);
    }
    accepts(...types) {
        const acceptValue = this.#serverRequest.headers.get("Accept");
        if (!acceptValue) {
            return;
        }
        if (types.length) {
            return preferredMediaTypes(acceptValue, types)[0];
        }
        return preferredMediaTypes(acceptValue);
    }
    acceptsCharsets(...charsets) {
        const acceptCharsetValue = this.#serverRequest.headers.get("Accept-Charset");
        if (!acceptCharsetValue) {
            return;
        }
        if (charsets.length) {
            return preferredCharsets(acceptCharsetValue, charsets)[0];
        }
        return preferredCharsets(acceptCharsetValue);
    }
    acceptsEncodings(...encodings) {
        const acceptEncodingValue = this.#serverRequest.headers.get("Accept-Encoding");
        if (!acceptEncodingValue) {
            return;
        }
        if (encodings.length) {
            return preferredEncodings(acceptEncodingValue, encodings)[0];
        }
        return preferredEncodings(acceptEncodingValue);
    }
    acceptsLanguages(...langs) {
        const acceptLanguageValue = this.#serverRequest.headers.get("Accept-Language");
        if (!acceptLanguageValue) {
            return;
        }
        if (langs.length) {
            return preferredLanguages(acceptLanguageValue, langs)[0];
        }
        return preferredLanguages(acceptLanguageValue);
    }
    body(options = {
    }) {
        return this.#body.get(options);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { hasBody , headers , ip , ips , method , secure: secure2 , url  } = this;
        return `${this.constructor.name} ${inspect({
            hasBody,
            headers,
            ip,
            ips,
            method,
            secure: secure2,
            url: url.toString()
        })}`;
    }
}
class AsyncIterableReader {
    #asyncIterator;
    #closed = false;
    #current;
    #processValue;
    constructor(asyncIterable, processValue){
        this.#asyncIterator = asyncIterable[Symbol.asyncIterator]();
        this.#processValue = processValue;
    }
     #close() {
        if (this.#asyncIterator.return) {
            this.#asyncIterator.return();
        }
        this.#asyncIterator = undefined;
        this.#closed = true;
    }
    async read(p) {
        if (this.#closed) {
            return null;
        }
        if (p.byteLength === 0) {
            this.#close();
            return 0;
        }
        if (!this.#current) {
            const { value: value3 , done  } = await this.#asyncIterator.next();
            if (done) {
                this.#close();
            }
            if (value3 !== undefined) {
                this.#current = this.#processValue(value3);
            }
        }
        if (!this.#current) {
            if (!this.#closed) {
                this.#close();
            }
            return null;
        }
        const len = copy(this.#current, p);
        if (len >= this.#current.byteLength) {
            this.#current = undefined;
        } else {
            this.#current = this.#current.slice(len);
        }
        return len;
    }
}
const REDIRECT_BACK = Symbol("redirect backwards");
const encoder2 = new TextEncoder();
function toUint8Array(body1) {
    let bodyText;
    if (BODY_TYPES.includes(typeof body1)) {
        bodyText = String(body1);
    } else {
        bodyText = JSON.stringify(body1);
    }
    return encoder2.encode(bodyText);
}
async function convertBodyToBodyInit(body1, type2) {
    let result;
    if (BODY_TYPES.includes(typeof body1)) {
        result = String(body1);
        type2 = type2 ?? (isHtml(result) ? "html" : "text/plain");
    } else if (isReader(body1)) {
        result = readableStreamFromReader(body1);
    } else if (ArrayBuffer.isView(body1) || body1 instanceof ArrayBuffer || body1 instanceof Blob || body1 instanceof URLSearchParams) {
        result = body1;
    } else if (body1 instanceof ReadableStream) {
        result = body1.pipeThrough(new Uint8ArrayTransformStream());
    } else if (body1 instanceof FormData) {
        result = body1;
        type2 = "multipart/form-data";
    } else if (body1 && typeof body1 === "object") {
        result = JSON.stringify(body1);
        type2 = type2 ?? "json";
    } else if (typeof body1 === "function") {
        const result1 = body1.call(null);
        return convertBodyToBodyInit(await result1, type2);
    } else if (body1) {
        throw new TypeError("Response body was set but could not be converted.");
    }
    return [
        result,
        type2
    ];
}
async function convertBodyToStdBody(body1, type2) {
    let result;
    if (BODY_TYPES.includes(typeof body1)) {
        const bodyText = String(body1);
        result = encoder2.encode(bodyText);
        type2 = type2 ?? (isHtml(bodyText) ? "html" : "text/plain");
    } else if (body1 instanceof Uint8Array || isReader(body1)) {
        result = body1;
    } else if (body1 instanceof ReadableStream) {
        result = readerFromStreamReader(body1.pipeThrough(new Uint8ArrayTransformStream()).getReader());
    } else if (isAsyncIterable(body1)) {
        result = new AsyncIterableReader(body1, toUint8Array);
    } else if (body1 && typeof body1 === "object") {
        result = encoder2.encode(JSON.stringify(body1));
        type2 = type2 ?? "json";
    } else if (typeof body1 === "function") {
        const result1 = body1.call(null);
        return convertBodyToStdBody(await result1, type2);
    } else if (body1) {
        throw new TypeError("Response body was set but could not be converted.");
    }
    return [
        result,
        type2
    ];
}
class Response1 {
    #body;
    #bodySet = false;
    #domResponse;
    #headers = new Headers();
    #request;
    #resources = [];
    #serverResponse;
    #status;
    #type;
    #writable = true;
    async #getBodyInit() {
        const [body1, type2] = await convertBodyToBodyInit(this.body, this.type);
        this.type = type2;
        return body1;
    }
    async #getStdBody() {
        const [body1, type2] = await convertBodyToStdBody(this.body, this.type);
        this.type = type2;
        return body1;
    }
     #setContentType() {
        if (this.type) {
            const contentTypeString = contentType(this.type);
            if (contentTypeString && !this.headers.has("Content-Type")) {
                this.headers.append("Content-Type", contentTypeString);
            }
        }
    }
    get body() {
        return this.#body;
    }
    set body(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#bodySet = true;
        this.#body = value;
    }
    get headers() {
        return this.#headers;
    }
    set headers(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#headers = value;
    }
    get status() {
        if (this.#status) {
            return this.#status;
        }
        return this.body != null ? Status.OK : this.#bodySet ? Status.NoContent : Status.NotFound;
    }
    set status(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#status = value;
    }
    get type() {
        return this.#type;
    }
    set type(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#type = value;
    }
    get writable() {
        return this.#writable;
    }
    constructor(request2){
        this.#request = request2;
    }
    addResource(rid) {
        this.#resources.push(rid);
    }
    destroy(closeResources = true) {
        this.#writable = false;
        this.#body = undefined;
        this.#serverResponse = undefined;
        this.#domResponse = undefined;
        if (closeResources) {
            for (const rid of this.#resources){
                Deno.close(rid);
            }
        }
    }
    redirect(url, alt = "/") {
        if (url === REDIRECT_BACK) {
            url = this.#request.headers.get("Referer") ?? String(alt);
        } else if (typeof url === "object") {
            url = String(url);
        }
        this.headers.set("Location", encodeUrl(url));
        if (!this.status || !isRedirectStatus(this.status)) {
            this.status = Status.Found;
        }
        if (this.#request.accepts("html")) {
            url = encodeURI(url);
            this.type = "text/html; charset=utf-8";
            this.body = `Redirecting to <a href="${url}">${url}</a>.`;
            return;
        }
        this.type = "text/plain; charset=utf-8";
        this.body = `Redirecting to ${url}.`;
    }
    async toDomResponse() {
        if (this.#domResponse) {
            return this.#domResponse;
        }
        const bodyInit = await this.#getBodyInit();
        this.#setContentType();
        const { headers  } = this;
        if (!(bodyInit || headers.has("Content-Type") || headers.has("Content-Length"))) {
            headers.append("Content-Length", "0");
        }
        this.#writable = false;
        const status = this.status;
        const responseInit = {
            headers,
            status,
            statusText: STATUS_TEXT.get(status)
        };
        return this.#domResponse = new DomResponse(bodyInit, responseInit);
    }
    async toServerResponse() {
        if (this.#serverResponse) {
            return this.#serverResponse;
        }
        const body1 = await this.#getStdBody();
        this.#setContentType();
        const { headers  } = this;
        if (!(body1 || headers.has("Content-Type") || headers.has("Content-Length"))) {
            headers.append("Content-Length", "0");
        }
        this.#writable = false;
        return this.#serverResponse = {
            body: body1,
            headers,
            status: this.status
        };
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { body: body1 , headers , status , type: type2 , writable  } = this;
        return `${this.constructor.name} ${inspect({
            body: body1,
            headers,
            status,
            type: type2,
            writable
        })}`;
    }
}
function isFileInfo(value3) {
    return Boolean(value3 && typeof value3 === "object" && "mtime" in value3 && "size" in value3);
}
function calcStatTag(entity) {
    const mtime = entity.mtime?.getTime().toString(16) ?? "0";
    const size5 = entity.size.toString(16);
    return `"${size5}-${mtime}"`;
}
function calcEntityTag(entity) {
    if (entity.length === 0) {
        return `"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk="`;
    }
    const hash = createHash("sha1").update(entity).toString("base64").substring(0, 27);
    return `"${entity.length.toString(16)}-${hash}"`;
}
function calculate(entity, options4 = {
}) {
    const weak = options4.weak ?? isFileInfo(entity);
    const tag = isFileInfo(entity) ? calcStatTag(entity) : calcEntityTag(entity);
    return weak ? `W/${tag}` : tag;
}
function ifNoneMatch(value3, entity, options4 = {
}) {
    if (value3.trim() === "*") {
        return false;
    }
    const etag = calculate(entity, options4);
    const tags = value3.split(/\s*,\s*/);
    return !tags.includes(etag);
}
const ETAG_RE = /(?:W\/)?"[ !#-\x7E\x80-\xFF]+"/;
function ifRange(value3, mtime, entity) {
    if (value3) {
        const matches1 = value3.match(ETAG_RE);
        if (matches1) {
            const [match] = matches1;
            if (calculate(entity) === match) {
                return true;
            }
        } else {
            return new Date(value3).getTime() >= mtime;
        }
    }
    return false;
}
function parseRange(value3, size5) {
    const ranges = [];
    const [unit, rangesStr] = value3.split("=");
    if (unit !== "bytes") {
        throw createHttpError(Status.RequestedRangeNotSatisfiable);
    }
    for (const range of rangesStr.split(/\s*,\s+/)){
        const item = range.split("-");
        if (item.length !== 2) {
            throw createHttpError(Status.RequestedRangeNotSatisfiable);
        }
        const [startStr, endStr] = item;
        let start;
        let end;
        try {
            if (startStr === "") {
                start = size5 - parseInt(endStr, 10) - 1;
                end = size5 - 1;
            } else if (endStr === "") {
                start = parseInt(startStr, 10);
                end = size5 - 1;
            } else {
                start = parseInt(startStr, 10);
                end = parseInt(endStr, 10);
            }
        } catch  {
            throw createHttpError();
        }
        if (start < 0 || start >= size5 || end < 0 || end >= size5 || start >= end) {
            throw createHttpError(Status.RequestedRangeNotSatisfiable);
        }
        ranges.push({
            start,
            end
        });
    }
    return ranges;
}
async function readRange(file, range) {
    let length = range.end - range.start + 1;
    assert1(length);
    await file.seek(range.start, Deno.SeekMode.Start);
    const result = new Uint8Array(length);
    let off = 0;
    while(length){
        const p2 = new Uint8Array(Math.min(length, 16640));
        const nread = await file.read(p2);
        assert1(nread !== null, "Unexpected EOF encountered when reading a range.");
        assert1(nread > 0, "Unexpected read of 0 bytes while reading a range.");
        copy(p2, result, off);
        off += nread;
        length -= nread;
        assert1(length >= 0, "Unexpected length remaining.");
    }
    return result;
}
const encoder3 = new TextEncoder();
class MultiPartStream extends ReadableStream {
    #contentLength;
    #postscript;
    #preamble;
    constructor(file, type2, ranges, size5, boundary1){
        super({
            pull: async (controller)=>{
                const range = ranges.shift();
                if (!range) {
                    controller.enqueue(this.#postscript);
                    controller.close();
                    if (!(file instanceof Uint8Array)) {
                        file.close();
                    }
                    return;
                }
                let bytes;
                if (file instanceof Uint8Array) {
                    bytes = file.subarray(range.start, range.end + 1);
                } else {
                    bytes = await readRange(file, range);
                }
                const rangeHeader = encoder3.encode(`Content-Range: ${range.start}-${range.end}/${size5}\n\n`);
                controller.enqueue(concat(this.#preamble, rangeHeader, bytes));
            }
        });
        const resolvedType = contentType(type2);
        if (!resolvedType) {
            throw new TypeError(`Could not resolve media type for "${type2}"`);
        }
        this.#preamble = encoder3.encode(`\n--${boundary1}\nContent-Type: ${resolvedType}\n`);
        this.#postscript = encoder3.encode(`\n--${boundary1}--\n`);
        this.#contentLength = ranges.reduce((prev, { start , end  })=>{
            return prev + this.#preamble.length + String(start).length + String(end).length + String(size5).length + 20 + (end - start);
        }, this.#postscript.length);
    }
    contentLength() {
        return this.#contentLength;
    }
}
const BOUNDARY = getBoundary();
function isHidden(path1) {
    const pathArr = path1.split("/");
    for (const segment of pathArr){
        if (segment[0] === "." && segment !== "." && segment !== "..") {
            return true;
        }
        return false;
    }
}
async function exists(path1) {
    try {
        return (await Deno.stat(path1)).isFile;
    } catch  {
        return false;
    }
}
async function getEntity(path1, mtime, stats, maxbuffer, response2) {
    let body1;
    let entity;
    const file1 = await Deno.open(path1, {
        read: true
    });
    if (stats.size < maxbuffer) {
        const buffer = await readAll(file1);
        file1.close();
        body1 = entity = buffer;
    } else {
        response2.addResource(file1.rid);
        body1 = file1;
        entity = {
            mtime: new Date(mtime),
            size: stats.size
        };
    }
    return [
        body1,
        entity
    ];
}
async function sendRange(response2, body1, range, size6) {
    const ranges1 = parseRange(range, size6);
    if (ranges1.length === 0) {
        throw createHttpError(Status.RequestedRangeNotSatisfiable);
    }
    response2.status = Status.PartialContent;
    if (ranges1.length === 1) {
        const [byteRange] = ranges1;
        response2.headers.set("Content-Length", String(byteRange.end - byteRange.start + 1));
        response2.headers.set("Content-Range", `bytes ${byteRange.start}-${byteRange.end}/${size6}`);
        if (body1 instanceof Uint8Array) {
            response2.body = body1.slice(byteRange.start, byteRange.end + 1);
        } else {
            await body1.seek(byteRange.start, Deno.SeekMode.Start);
            response2.body = new LimitedReader(body1, byteRange.end - byteRange.start);
        }
    } else {
        assert1(response2.type);
        response2.headers.set("content-type", `multipart/byteranges; boundary=${BOUNDARY}`);
        const multipartBody = new MultiPartStream(body1, response2.type, ranges1, size6, BOUNDARY);
        response2.headers.set("content-length", String(multipartBody.contentLength()));
        response2.body = multipartBody;
    }
}
async function send({ request: request3 , response: response2  }, path1, options4 = {
    root: ""
}) {
    const { brotli =true , contentTypes ={
    } , extensions: extensions1 , format: format4 = true , gzip =true , hidden =false , immutable =false , index , maxbuffer =1048576 , maxage =0 , root ,  } = options4;
    const trailingSlash = path1[path1.length - 1] === "/";
    path1 = decodeComponent(path1.substr(parse2(path1).root.length));
    if (index && trailingSlash) {
        path1 += index;
    }
    if (!hidden && isHidden(path1)) {
        throw createHttpError(403);
    }
    path1 = resolvePath(root, path1);
    let encodingExt = "";
    if (brotli && request3.acceptsEncodings("br", "identity") === "br" && await exists(`${path1}.br`)) {
        path1 = `${path1}.br`;
        response2.headers.set("Content-Encoding", "br");
        response2.headers.delete("Content-Length");
        encodingExt = ".br";
    } else if (gzip && request3.acceptsEncodings("gzip", "identity") === "gzip" && await exists(`${path1}.gz`)) {
        path1 = `${path1}.gz`;
        response2.headers.set("Content-Encoding", "gzip");
        response2.headers.delete("Content-Length");
        encodingExt = ".gz";
    }
    if (extensions1 && !/\.[^/]*$/.exec(path1)) {
        for (let ext of extensions1){
            if (!/^\./.exec(ext)) {
                ext = `.${ext}`;
            }
            if (await exists(`${path1}${ext}`)) {
                path1 += ext;
                break;
            }
        }
    }
    let stats;
    try {
        stats = await Deno.stat(path1);
        if (stats.isDirectory) {
            if (format4 && index) {
                path1 += `/${index}`;
                stats = await Deno.stat(path1);
            } else {
                return;
            }
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            throw createHttpError(404, err.message);
        }
        throw createHttpError(500, err.message);
    }
    let mtime = null;
    if (response2.headers.has("Last-Modified")) {
        mtime = new Date(response2.headers.get("Last-Modified")).getTime();
    } else if (stats.mtime) {
        mtime = stats.mtime.getTime();
        mtime -= mtime % 1000;
        response2.headers.set("Last-Modified", new Date(mtime).toUTCString());
    }
    if (!response2.headers.has("Cache-Control")) {
        const directives = [
            `max-age=${maxage / 1000 | 0}`
        ];
        if (immutable) {
            directives.push("immutable");
        }
        response2.headers.set("Cache-Control", directives.join(","));
    }
    if (!response2.type) {
        response2.type = encodingExt !== "" ? extname2(basename2(path1, encodingExt)) : contentTypes[extname2(path1)] ?? extname2(path1);
    }
    let entity = null;
    let body1 = null;
    if (request3.headers.has("If-None-Match") && mtime) {
        [body1, entity] = await getEntity(path1, mtime, stats, maxbuffer, response2);
        if (!ifNoneMatch(request3.headers.get("If-None-Match"), entity)) {
            response2.headers.set("ETag", calculate(entity));
            response2.status = 304;
            return path1;
        }
    }
    if (request3.headers.has("If-Modified-Since") && mtime) {
        const ifModifiedSince = new Date(request3.headers.get("If-Modified-Since"));
        if (ifModifiedSince.getTime() >= mtime) {
            response2.status = 304;
            return path1;
        }
    }
    if (!body1 || !entity) {
        [body1, entity] = await getEntity(path1, mtime ?? 0, stats, maxbuffer, response2);
    }
    if (request3.headers.has("If-Range") && mtime && ifRange(request3.headers.get("If-Range"), mtime, entity) && request3.headers.has("Range")) {
        await sendRange(response2, body1, request3.headers.get("Range"), stats.size);
        return path1;
    }
    if (request3.headers.has("Range")) {
        await sendRange(response2, body1, request3.headers.get("Range"), stats.size);
        return path1;
    }
    response2.headers.set("Content-Length", String(stats.size));
    response2.body = body1;
    if (!response2.headers.has("ETag")) {
        response2.headers.set("ETag", calculate(entity));
    }
    if (!response2.headers.has("Accept-Ranges")) {
        response2.headers.set("Accept-Ranges", "bytes");
    }
    return path1;
}
const encoder4 = new TextEncoder();
class CloseEvent1 extends Event {
    constructor(eventInit){
        super("close", eventInit);
    }
}
class ServerSentEvent extends Event {
    #data;
    #id;
    #type;
    constructor(type3, data1, { replacer , space , ...eventInit1 } = {
    }){
        super(type3, eventInit1);
        this.#type = type3;
        try {
            this.#data = typeof data1 === "string" ? data1 : JSON.stringify(data1, replacer, space);
        } catch (e) {
            assert1(e instanceof Error);
            throw new TypeError(`data could not be coerced into a serialized string.\n  ${e.message}`);
        }
        const { id  } = eventInit1;
        this.#id = id;
    }
    get data() {
        return this.#data;
    }
    get id() {
        return this.#id;
    }
    toString() {
        const data1 = `data: ${this.#data.split("\n").join("\ndata: ")}\n`;
        return `${this.#type === "__message" ? "" : `event: ${this.#type}\n`}${this.#id ? `id: ${String(this.#id)}\n` : ""}${data1}\n`;
    }
}
const response2 = `HTTP/1.1 200 OK\n`;
const responseHeaders = new Headers([
    [
        "Connection",
        "Keep-Alive"
    ],
    [
        "Content-Type",
        "text/event-stream"
    ],
    [
        "Cache-Control",
        "no-cache"
    ],
    [
        "Keep-Alive",
        `timeout=${Number.MAX_SAFE_INTEGER}`
    ], 
]);
class SSEStreamTarget extends EventTarget {
    #closed = false;
    #context;
    #controller;
    #keepAliveId;
     #error(error) {
        console.log("error", error);
        this.dispatchEvent(new CloseEvent1({
            cancelable: false
        }));
        const errorEvent = new ErrorEvent("error", {
            error
        });
        this.dispatchEvent(errorEvent);
        this.#context.app.dispatchEvent(errorEvent);
    }
     #push(payload) {
        if (!this.#controller) {
            this.#error(new Error("The controller has not been set."));
            return;
        }
        if (this.#closed) {
            return;
        }
        this.#controller.enqueue(encoder4.encode(payload));
    }
    get closed() {
        return this.#closed;
    }
    constructor(context2, { headers , keepAlive =false  } = {
    }){
        super();
        this.#context = context2;
        context2.response.body = new ReadableStream({
            start: (controller)=>{
                this.#controller = controller;
            },
            cancel: (error)=>{
                if (error instanceof Error && error.message.includes("connection closed")) {
                    this.close();
                } else {
                    this.#error(error);
                }
            }
        });
        if (headers) {
            for (const [key3, value3] of headers){
                context2.response.headers.set(key3, value3);
            }
        }
        for (const [key3, value3] of responseHeaders){
            context2.response.headers.set(key3, value3);
        }
        this.addEventListener("close", ()=>{
            this.#closed = true;
            if (this.#keepAliveId != null) {
                clearInterval(this.#keepAliveId);
                this.#keepAliveId = undefined;
            }
            if (this.#controller) {
                try {
                    this.#controller.close();
                } catch  {
                }
            }
        });
        if (keepAlive) {
            const interval = typeof keepAlive === "number" ? keepAlive : 30000;
            this.#keepAliveId = setInterval(()=>{
                this.dispatchComment("keep-alive comment");
            }, interval);
        }
    }
    close() {
        this.dispatchEvent(new CloseEvent1({
            cancelable: false
        }));
        return Promise.resolve();
    }
    dispatchComment(comment) {
        this.#push(`: ${comment.split("\n").join("\n: ")}\n\n`);
        return true;
    }
    dispatchMessage(data) {
        const event = new ServerSentEvent("__message", data);
        return this.dispatchEvent(event);
    }
    dispatchEvent(event) {
        const dispatched = super.dispatchEvent(event);
        if (dispatched && event instanceof ServerSentEvent) {
            this.#push(String(event));
        }
        return dispatched;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            "#closed": this.#closed,
            "#context": this.#context
        })}`;
    }
}
class SSEStdLibTarget extends EventTarget {
    #app;
    #closed = false;
    #keepAliveId;
    #prev = Promise.resolve();
    #ready;
    #serverRequest;
    #writer;
    async #send(payload, prev) {
        if (this.#closed) {
            return;
        }
        if (this.#ready !== true) {
            await this.#ready;
            this.#ready = true;
        }
        try {
            await prev;
            await this.#writer.write(encoder4.encode(payload));
            await this.#writer.flush();
        } catch (error) {
            this.dispatchEvent(new CloseEvent1({
                cancelable: false
            }));
            const errorEvent = new ErrorEvent("error", {
                error
            });
            this.dispatchEvent(errorEvent);
            this.#app.dispatchEvent(errorEvent);
        }
    }
    async #setup(overrideHeaders) {
        const headers1 = new Headers(responseHeaders);
        if (overrideHeaders) {
            for (const [key4, value4] of overrideHeaders){
                headers1.set(key4, value4);
            }
        }
        let payload = response2;
        for (const [key4, value4] of headers1){
            payload += `${key4}: ${value4}\n`;
        }
        payload += `\n`;
        try {
            await this.#writer.write(encoder4.encode(payload));
            await this.#writer.flush();
        } catch (error) {
            this.dispatchEvent(new CloseEvent1({
                cancelable: false
            }));
            const errorEvent = new ErrorEvent("error", {
                error
            });
            this.dispatchEvent(errorEvent);
            this.#app.dispatchEvent(errorEvent);
            throw error;
        }
    }
    get closed() {
        return this.#closed;
    }
    constructor(context1, { headers: headers1 , keepAlive: keepAlive1 = false  } = {
    }){
        super();
        this.#app = context1.app;
        assert1(!(context1.request.originalRequest instanceof NativeRequest));
        this.#serverRequest = context1.request.originalRequest;
        this.#writer = this.#serverRequest.w;
        this.addEventListener("close", ()=>{
            this.#closed = true;
            if (this.#keepAliveId != null) {
                clearInterval(this.#keepAliveId);
                this.#keepAliveId = undefined;
            }
            try {
                this.#serverRequest.conn.close();
            } catch (error) {
                if (!(error instanceof Deno.errors.BadResource)) {
                    const errorEvent = new ErrorEvent("error", {
                        error
                    });
                    this.dispatchEvent(errorEvent);
                    this.#app.dispatchEvent(errorEvent);
                }
            }
        });
        if (keepAlive1) {
            const interval = typeof keepAlive1 === "number" ? keepAlive1 : 30000;
            this.#keepAliveId = setInterval(()=>{
                this.dispatchComment("keep-alive comment");
            }, interval);
        }
        this.#ready = this.#setup(headers1);
    }
    async close() {
        if (this.#ready !== true) {
            await this.#ready;
        }
        await this.#prev;
        this.dispatchEvent(new CloseEvent1({
            cancelable: false
        }));
    }
    dispatchComment(comment) {
        this.#prev = this.#send(`: ${comment.split("\n").join("\n: ")}\n\n`, this.#prev);
        return true;
    }
    dispatchMessage(data) {
        const event = new ServerSentEvent("__message", data);
        return this.dispatchEvent(event);
    }
    dispatchEvent(event) {
        const dispatched = super.dispatchEvent(event);
        if (dispatched && event instanceof ServerSentEvent) {
            this.#prev = this.#send(String(event), this.#prev);
        }
        return dispatched;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            "closed": this.closed
        })}`;
    }
}
class WebSocketShim extends EventTarget {
    #binaryType = "blob";
    #protocol = "";
    #readyState = WebSocket.CONNECTING;
    #socket;
    #url;
    #wasClean = false;
     #getBinaryData(data) {
        if (this.#binaryType === "arraybuffer") {
            return data.buffer;
        }
        return new Blob([
            data
        ]);
    }
     #listen() {
        queueMicrotask(async ()=>{
            for await (const event of this.#socket){
                if (this.#readyState === WebSocket.CONNECTING) {
                    this.#readyState = WebSocket.OPEN;
                    this.dispatchEvent(new Event("open", {
                        cancelable: false
                    }));
                }
                if (this.#readyState === WebSocket.CLOSING && !isWebSocketCloseEvent(event)) {
                    const error = new Error("Received an event while closing.");
                    this.dispatchEvent(new ErrorEvent("error", {
                        error,
                        cancelable: false
                    }));
                }
                if (isWebSocketCloseEvent(event)) {
                    this.#readyState = WebSocket.CLOSED;
                    const { code , reason  } = event;
                    const wasClean = this.#wasClean;
                    this.dispatchEvent(new CloseEvent("close", {
                        code,
                        reason,
                        wasClean,
                        cancelable: false
                    }));
                    return;
                } else if (isWebSocketPingEvent(event) || isWebSocketPongEvent(event)) {
                    const [type4, data2] = event;
                    this.dispatchEvent(new MessageEvent("message", {
                        data: type4,
                        cancelable: false
                    }));
                    this.dispatchEvent(new MessageEvent("message", {
                        data: data2,
                        cancelable: false
                    }));
                } else {
                    const data2 = typeof event === "string" ? event : this.#getBinaryData(event);
                    this.dispatchEvent(new MessageEvent("message", {
                        data: data2,
                        cancelable: false
                    }));
                }
                if (this.#readyState === WebSocket.CLOSED) {
                    return;
                }
            }
        });
    }
    get binaryType() {
        return this.#binaryType;
    }
    set binaryType(value) {
        this.#binaryType = value;
    }
    get bufferedAmount() {
        return 0;
    }
    get extensions() {
        return "";
    }
    onclose = null;
    onerror = null;
    onmessage = null;
    onopen = null;
    get protocol() {
        return this.#protocol;
    }
    get readyState() {
        return this.#readyState;
    }
    get url() {
        return this.#url;
    }
    constructor(socket, url, protocol = ""){
        super();
        this.#protocol = protocol;
        this.#socket = socket;
        this.#url = url;
        this.#listen();
    }
    close(code, reason) {
        queueMicrotask(async ()=>{
            try {
                this.#readyState = WebSocket.CLOSING;
                await this.#socket.close(code, reason);
                this.#wasClean = true;
            } catch (error) {
                this.dispatchEvent(new ErrorEvent("error", {
                    error
                }));
            }
        });
    }
    send(data) {
        queueMicrotask(async ()=>{
            try {
                let d;
                if (typeof data === "string") {
                    d = data;
                } else if (data instanceof Blob) {
                    d = new Uint8Array(await data.arrayBuffer());
                } else if (ArrayBuffer.isView(data)) {
                    d = new Uint8Array(data.buffer);
                } else {
                    d = new Uint8Array(data);
                }
                await this.#socket.send(d);
            } catch (error) {
                this.dispatchEvent(new ErrorEvent("error", {
                    error,
                    cancelable: false
                }));
            }
        });
    }
    dispatchEvent(event) {
        if (event.type === "error" && this.onerror) {
            this.onerror.call(this, event);
        } else if (event.type === "close" && event instanceof CloseEvent && this.onclose) {
            this.onclose.call(this, event);
        } else if (event.type === "message" && event instanceof MessageEvent && this.onmessage) {
            this.onmessage.call(this, event);
        } else if (event.type === "open" && this.onopen) {
            this.onopen.call(this, event);
        }
        if (!event.defaultPrevented) {
            return super.dispatchEvent(event);
        } else {
            return false;
        }
    }
    get CLOSED() {
        return WebSocket.CLOSED;
    }
    get CLOSING() {
        return WebSocket.CLOSING;
    }
    get CONNECTING() {
        return WebSocket.CONNECTING;
    }
    get OPEN() {
        return WebSocket.OPEN;
    }
}
class Context {
    #socket;
    #sse;
    app;
    cookies;
    get isUpgradable() {
        return acceptable(this.request);
    }
    respond;
    request;
    response;
    get socket() {
        return this.#socket;
    }
    state;
    constructor(app2, serverRequest1, state1, secure2 = false){
        this.app = app2;
        this.state = state1;
        this.request = new Request1(serverRequest1, app2.proxy, secure2);
        this.respond = true;
        this.response = new Response1(this.request);
        this.cookies = new Cookies(this.request, this.response, {
            keys: this.app.keys,
            secure: this.request.secure
        });
    }
    assert(condition, errorStatus = 500, message, props) {
        if (condition) {
            return;
        }
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    send(options) {
        const { path: path1 = this.request.url.pathname , ...sendOptions } = options;
        return send(this, path1, sendOptions);
    }
    sendEvents(options) {
        if (!this.#sse) {
            if (this.request.originalRequest instanceof NativeRequest) {
                this.#sse = new SSEStreamTarget(this, options);
            } else {
                this.respond = false;
                this.#sse = new SSEStdLibTarget(this, options);
            }
        }
        return this.#sse;
    }
    throw(errorStatus, message, props) {
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    async upgrade(options) {
        if (this.#socket) {
            return this.#socket;
        }
        if (this.request.originalRequest instanceof NativeRequest) {
            this.#socket = this.request.originalRequest.upgrade(options);
        } else {
            const { conn: conn2 , r: bufReader1 , w: bufWriter1 , headers: headers2  } = this.request.originalRequest;
            this.#socket = new WebSocketShim(await acceptWebSocket({
                conn: conn2,
                bufReader: bufReader1,
                bufWriter: bufWriter1,
                headers: headers2
            }), this.request.url.toString(), options?.protocol);
        }
        this.respond = false;
        return this.#socket;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { app: app3 , cookies , isUpgradable , respond , request: request4 , response: response3 , socket: socket1 , state: state1 ,  } = this;
        return `${this.constructor.name} ${inspect({
            app: app3,
            cookies,
            isUpgradable,
            respond,
            request: request4,
            response: response3,
            socket: socket1,
            state: state1
        })}`;
    }
}
class HttpServerStd {
    #server;
    constructor(_app, options4){
        this.#server = isListenTlsOptions(options4) ? serveTLS(options4) : serve(options4);
    }
    close() {
        this.#server.close();
    }
    [Symbol.asyncIterator]() {
        return this.#server[Symbol.asyncIterator]();
    }
}
function compareArrayBuffer(a, b) {
    assert1(a.byteLength === b.byteLength, "ArrayBuffer lengths must match.");
    const va = new DataView(a);
    const vb = new DataView(b);
    const length = va.byteLength;
    let out = 0;
    let i2 = -1;
    while((++i2) < length){
        out |= va.getUint8(i2) ^ vb.getUint8(i2);
    }
    return out === 0;
}
function compare(a, b) {
    const key4 = new Uint8Array(32);
    globalThis.crypto.getRandomValues(key4);
    const ah = new HmacSha256(key4).update(a).arrayBuffer();
    const bh = new HmacSha256(key4).update(b).arrayBuffer();
    return compareArrayBuffer(ah, bh);
}
const replacements = {
    "/": "_",
    "+": "-",
    "=": ""
};
class KeyStack {
    #keys;
    get length() {
        return this.#keys.length;
    }
    constructor(keys1){
        if (!(0 in keys1)) {
            throw new TypeError("keys must contain at least one value");
        }
        this.#keys = keys1;
    }
     #sign(data, key) {
        return btoa(String.fromCharCode.apply(undefined, new Uint8Array(new HmacSha256(key).update(data).arrayBuffer()))).replace(/\/|\+|=/g, (c)=>replacements[c]
        );
    }
    sign(data) {
        return this.#sign(data, this.#keys[0]);
    }
    verify(data, digest) {
        return this.indexOf(data, digest) > -1;
    }
    indexOf(data, digest) {
        for(let i2 = 0; i2 < this.#keys.length; i2++){
            if (compare(digest, this.#sign(data, this.#keys[i2]))) {
                return i2;
            }
        }
        return -1;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            length: this.length
        })}`;
    }
}
function compose(middleware) {
    return function composedMiddleware(context2, next) {
        let index = -1;
        async function dispatch(i2) {
            if (i2 <= index) {
                throw new Error("next() called multiple times.");
            }
            index = i2;
            let fn = middleware[i2];
            if (i2 === middleware.length) {
                fn = next;
            }
            if (!fn) {
                return;
            }
            await fn(context2, dispatch.bind(null, i2 + 1));
        }
        return dispatch(0);
    };
}
const objectCloneMemo = new WeakMap();
function cloneArrayBuffer(srcBuffer, srcByteOffset, srcLength, _cloneConstructor) {
    return srcBuffer.slice(srcByteOffset, srcByteOffset + srcLength);
}
function cloneValue(value4) {
    switch(typeof value4){
        case "number":
        case "string":
        case "boolean":
        case "undefined":
        case "bigint":
            return value4;
        case "object":
            {
                if (objectCloneMemo.has(value4)) {
                    return objectCloneMemo.get(value4);
                }
                if (value4 === null) {
                    return value4;
                }
                if (value4 instanceof Date) {
                    return new Date(value4.valueOf());
                }
                if (value4 instanceof RegExp) {
                    return new RegExp(value4);
                }
                if (value4 instanceof SharedArrayBuffer) {
                    return value4;
                }
                if (value4 instanceof ArrayBuffer) {
                    const cloned = cloneArrayBuffer(value4, 0, value4.byteLength, ArrayBuffer);
                    objectCloneMemo.set(value4, cloned);
                    return cloned;
                }
                if (ArrayBuffer.isView(value4)) {
                    const clonedBuffer = cloneValue(value4.buffer);
                    let length;
                    if (value4 instanceof DataView) {
                        length = value4.byteLength;
                    } else {
                        length = value4.length;
                    }
                    return new value4.constructor(clonedBuffer, value4.byteOffset, length);
                }
                if (value4 instanceof Map) {
                    const clonedMap = new Map();
                    objectCloneMemo.set(value4, clonedMap);
                    value4.forEach((v, k)=>{
                        clonedMap.set(cloneValue(k), cloneValue(v));
                    });
                    return clonedMap;
                }
                if (value4 instanceof Set) {
                    const clonedSet = new Set([
                        ...value4
                    ].map(cloneValue));
                    objectCloneMemo.set(value4, clonedSet);
                    return clonedSet;
                }
                const clonedObj = {
                };
                objectCloneMemo.set(value4, clonedObj);
                const sourceKeys = Object.getOwnPropertyNames(value4);
                for (const key5 of sourceKeys){
                    clonedObj[key5] = cloneValue(value4[key5]);
                }
                Reflect.setPrototypeOf(clonedObj, Reflect.getPrototypeOf(value4));
                return clonedObj;
            }
        case "symbol":
        case "function":
        default:
            throw new DOMException("Uncloneable value in stream", "DataCloneError");
    }
}
const { core  } = Deno;
function structuredClone(value4) {
    return core ? core.deserialize(core.serialize(value4)) : cloneValue(value4);
}
function cloneState(state1) {
    const clone = {
    };
    for (const [key5, value4] of Object.entries(state1)){
        try {
            const clonedValue = structuredClone(value4);
            clone[key5] = clonedValue;
        } catch  {
        }
    }
    return clone;
}
const ADDR_REGEXP = /^\[?([^\]]*)\]?:([0-9]{1,5})$/;
class ApplicationErrorEvent extends ErrorEvent {
    context;
    constructor(eventInitDict){
        super("error", eventInitDict);
        this.context = eventInitDict.context;
    }
}
function logErrorListener({ error , context: context3  }) {
    if (error instanceof Error) {
        console.error(`[uncaught oak error]: ${error.name} - ${error.message}`);
    } else {
        console.error(`[uncaught oak error]\n`, error);
    }
    if (context3) {
        console.error(`\nrequest:`, {
            url: context3.request.url.toString(),
            method: context3.request.method,
            hasBody: context3.request.hasBody
        });
        console.error(`response:`, {
            status: context3.response.status,
            type: context3.response.type,
            hasBody: !!context3.response.body,
            writable: context3.response.writable
        });
    }
    if (error instanceof Error && error.stack) {
        console.error(`\n${error.stack.split("\n").slice(1).join("\n")}`);
    }
}
class ApplicationListenEvent extends Event {
    hostname;
    port;
    secure;
    serverType;
    constructor(eventInitDict1){
        super("listen", eventInitDict1);
        this.hostname = eventInitDict1.hostname;
        this.port = eventInitDict1.port;
        this.secure = eventInitDict1.secure;
        this.serverType = eventInitDict1.serverType;
    }
}
class Application extends EventTarget {
    #composedMiddleware;
    #contextState;
    #eventHandler;
    #keys;
    #middleware = [];
    #serverConstructor;
    get keys() {
        return this.#keys;
    }
    set keys(keys) {
        if (!keys) {
            this.#keys = undefined;
            return;
        } else if (Array.isArray(keys)) {
            this.#keys = new KeyStack(keys);
        } else {
            this.#keys = keys;
        }
    }
    proxy;
    state;
    constructor(options5 = {
    }){
        super();
        const { state: state2 , keys: keys3 , proxy: proxy2 , serverConstructor =hasNativeHttp() ? HttpServerNative : HttpServerStd , contextState ="clone" , logErrors =true ,  } = options5;
        this.proxy = proxy2 ?? false;
        this.keys = keys3;
        this.state = state2 ?? {
        };
        this.#serverConstructor = serverConstructor;
        this.#contextState = contextState;
        if (logErrors) {
            this.addEventListener("error", logErrorListener);
        }
    }
     #getComposed() {
        if (!this.#composedMiddleware) {
            this.#composedMiddleware = compose(this.#middleware);
        }
        return this.#composedMiddleware;
    }
     #getContextState() {
        switch(this.#contextState){
            case "alias":
                return this.state;
            case "clone":
                return cloneState(this.state);
            case "empty":
                return {
                };
            case "prototype":
                return Object.create(this.state);
        }
    }
     #handleError(context, error) {
        if (!(error instanceof Error)) {
            error = new Error(`non-error thrown: ${JSON.stringify(error)}`);
        }
        const { message: message3  } = error;
        this.dispatchEvent(new ApplicationErrorEvent({
            context,
            message: message3,
            error
        }));
        if (!context.response.writable) {
            return;
        }
        for (const key5 of context.response.headers.keys()){
            context.response.headers.delete(key5);
        }
        if (error.headers && error.headers instanceof Headers) {
            for (const [key6, value4] of error.headers){
                context.response.headers.set(key6, value4);
            }
        }
        context.response.type = "text";
        const status = context.response.status = Deno.errors && error instanceof Deno.errors.NotFound ? 404 : error.status && typeof error.status === "number" ? error.status : 500;
        context.response.body = error.expose ? error.message : STATUS_TEXT.get(status);
    }
    async #handleRequest(request, secure, state) {
        const context3 = new Context(this, request, this.#getContextState(), secure);
        let resolve3;
        const handlingPromise = new Promise((res)=>resolve3 = res
        );
        state.handling.add(handlingPromise);
        if (!state.closing && !state.closed) {
            try {
                await this.#getComposed()(context3);
            } catch (err) {
                this.#handleError(context3, err);
            }
        }
        if (context3.respond === false) {
            context3.response.destroy();
            resolve3();
            state.handling.delete(handlingPromise);
            return;
        }
        let closeResources = true;
        let response3;
        try {
            if (request instanceof NativeRequest) {
                closeResources = false;
                response3 = await context3.response.toDomResponse();
            } else {
                response3 = await context3.response.toServerResponse();
            }
        } catch (err) {
            this.#handleError(context3, err);
            if (request instanceof NativeRequest) {
                response3 = await context3.response.toDomResponse();
            } else {
                response3 = await context3.response.toServerResponse();
            }
        }
        assert1(response3);
        try {
            await request.respond(response3);
        } catch (err) {
            this.#handleError(context3, err);
        } finally{
            context3.response.destroy(closeResources);
            resolve3();
            state.handling.delete(handlingPromise);
            if (state.closing) {
                state.server.close();
                state.closed = true;
            }
        }
    }
    addEventListener(type, listener, options) {
        super.addEventListener(type, listener, options);
    }
    fetchEventHandler({ proxy =true , secure =true  } = {
    }) {
        if (this.#eventHandler) {
            return this.#eventHandler;
        }
        this.proxy = proxy;
        return this.#eventHandler = {
            handleEvent: async (requestEvent1)=>{
                let resolve3;
                let reject;
                const responsePromise = new Promise((res, rej)=>{
                    resolve3 = res;
                    reject = rej;
                });
                const respondedPromise = requestEvent1.respondWith(responsePromise);
                const response3 = await this.handle(requestEvent1.request, undefined, secure);
                if (response3) {
                    resolve3(response3);
                } else {
                    reject(new Error("No response returned from app handler."));
                }
                try {
                    await respondedPromise;
                } catch (error) {
                    this.dispatchEvent(new ApplicationErrorEvent({
                        error
                    }));
                }
            }
        };
    }
    handle = async (request4, secureOrConn, secure4 = false)=>{
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        let contextRequest;
        if (request4 instanceof Request) {
            assert1(isConn(secureOrConn) || typeof secureOrConn === "undefined");
            contextRequest = new NativeRequest({
                request: request4,
                respondWith () {
                    return Promise.resolve(undefined);
                }
            }, {
                conn: secureOrConn
            });
        } else {
            assert1(typeof secureOrConn === "boolean" || typeof secureOrConn === "undefined");
            secure4 = secureOrConn ?? false;
            contextRequest = request4;
        }
        const context3 = new Context(this, contextRequest, this.#getContextState(), secure4);
        try {
            await this.#getComposed()(context3);
        } catch (err) {
            this.#handleError(context3, err);
        }
        if (context3.respond === false) {
            context3.response.destroy();
            return;
        }
        try {
            const response3 = contextRequest instanceof NativeRequest ? await context3.response.toDomResponse() : await context3.response.toServerResponse();
            context3.response.destroy(false);
            return response3;
        } catch (err) {
            this.#handleError(context3, err);
            throw err;
        }
    };
    async listen(options) {
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        if (typeof options === "string") {
            const match = ADDR_REGEXP.exec(options);
            if (!match) {
                throw TypeError(`Invalid address passed: "${options}"`);
            }
            const [, hostname, portStr] = match;
            options = {
                hostname,
                port: parseInt(portStr, 10)
            };
        }
        const server = new this.#serverConstructor(this, options);
        const { signal  } = options;
        const state3 = {
            closed: false,
            closing: false,
            handling: new Set(),
            server
        };
        if (signal) {
            signal.addEventListener("abort", ()=>{
                if (!state3.handling.size) {
                    server.close();
                    state3.closed = true;
                }
                state3.closing = true;
            });
        }
        const { hostname , port , secure: secure4 = false  } = options;
        const serverType = server instanceof HttpServerStd ? "std" : server instanceof HttpServerNative ? "native" : "custom";
        this.dispatchEvent(new ApplicationListenEvent({
            hostname,
            port,
            secure: secure4,
            serverType
        }));
        try {
            for await (const request4 of server){
                this.#handleRequest(request4, secure4, state3);
            }
            await Promise.all(state3.handling);
        } catch (error) {
            const message3 = error instanceof Error ? error.message : "Application Error";
            this.dispatchEvent(new ApplicationErrorEvent({
                message: message3,
                error
            }));
        }
    }
    use(...middleware) {
        this.#middleware.push(...middleware);
        this.#composedMiddleware = undefined;
        return this;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { keys: keys4 , proxy: proxy3 , state: state3  } = this;
        return `${this.constructor.name} ${inspect({
            "#middleware": this.#middleware,
            keys: keys4,
            proxy: proxy3,
            state: state3
        })}`;
    }
}
function toUrl(url1, params = {
}, options6) {
    const tokens = parse3(url1);
    let replace = {
    };
    if (tokens.some((token)=>typeof token === "object"
    )) {
        replace = params;
    } else {
        options6 = params;
    }
    const toPath = compile(url1, options6);
    const replaced = toPath(replace);
    if (options6 && options6.query) {
        const url2 = new URL(replaced, "http://oak");
        if (typeof options6.query === "string") {
            url2.search = options6.query;
        } else {
            url2.search = String(options6.query instanceof URLSearchParams ? options6.query : new URLSearchParams(options6.query));
        }
        return `${url2.pathname}${url2.search}${url2.hash}`;
    }
    return replaced;
}
class Layer {
    #opts;
    #paramNames = [];
    #regexp;
    methods;
    name;
    path;
    stack;
    constructor(path2, methods1, middleware1, { name: name2 , ...opts } = {
    }){
        this.#opts = opts;
        this.name = name2;
        this.methods = [
            ...methods1
        ];
        if (this.methods.includes("GET")) {
            this.methods.unshift("HEAD");
        }
        this.stack = Array.isArray(middleware1) ? middleware1.slice() : [
            middleware1
        ];
        this.path = path2;
        this.#regexp = pathToRegexp(path2, this.#paramNames, this.#opts);
    }
    clone() {
        return new Layer(this.path, this.methods, this.stack, {
            name: this.name,
            ...this.#opts
        });
    }
    match(path) {
        return this.#regexp.test(path);
    }
    params(captures, existingParams = {
    }) {
        const params = existingParams;
        for(let i2 = 0; i2 < captures.length; i2++){
            if (this.#paramNames[i2]) {
                const c = captures[i2];
                params[this.#paramNames[i2].name] = c ? decodeComponent(c) : c;
            }
        }
        return params;
    }
    captures(path) {
        if (this.#opts.ignoreCaptures) {
            return [];
        }
        return path.match(this.#regexp)?.slice(1) ?? [];
    }
    url(params = {
    }, options) {
        const url1 = this.path.replace(/\(\.\*\)/g, "");
        return toUrl(url1, params, options);
    }
    param(param, fn) {
        const stack = this.stack;
        const params = this.#paramNames;
        const middleware1 = function(ctx, next) {
            const p2 = ctx.params[param];
            assert1(p2);
            return fn.call(this, p2, ctx, next);
        };
        middleware1.param = param;
        const names = params.map((p2)=>p2.name
        );
        const x = names.indexOf(param);
        if (x >= 0) {
            for(let i2 = 0; i2 < stack.length; i2++){
                const fn = stack[i2];
                if (!fn.param || names.indexOf(fn.param) > x) {
                    stack.splice(i2, 0, middleware1);
                    break;
                }
            }
        }
        return this;
    }
    setPrefix(prefix) {
        if (this.path) {
            this.path = this.path !== "/" || this.#opts.strict === true ? `${prefix}${this.path}` : prefix;
            this.#paramNames = [];
            this.#regexp = pathToRegexp(this.path, this.#paramNames, this.#opts);
        }
        return this;
    }
    toJSON() {
        return {
            methods: [
                ...this.methods
            ],
            middleware: [
                ...this.stack
            ],
            paramNames: this.#paramNames.map((key5)=>key5.name
            ),
            path: this.path,
            regexp: this.#regexp,
            options: {
                ...this.#opts
            }
        };
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            methods: this.methods,
            middleware: this.stack,
            options: this.#opts,
            paramNames: this.#paramNames.map((key5)=>key5.name
            ),
            path: this.path,
            regexp: this.#regexp
        })}`;
    }
}
class Router {
    #opts;
    #methods;
    #params = {
    };
    #stack = [];
     #match(path, method) {
        const matches1 = {
            path: [],
            pathAndMethod: [],
            route: false
        };
        for (const route of this.#stack){
            if (route.match(path)) {
                matches1.path.push(route);
                if (route.methods.length === 0 || route.methods.includes(method)) {
                    matches1.pathAndMethod.push(route);
                    if (route.methods.length) {
                        matches1.route = true;
                    }
                }
            }
        }
        return matches1;
    }
     #register(path, middlewares, methods, options = {
    }) {
        if (Array.isArray(path)) {
            for (const p2 of path){
                this.#register(p2, middlewares, methods, options);
            }
            return;
        }
        let layerMiddlewares = [];
        for (const middleware1 of middlewares){
            if (!middleware1.router) {
                layerMiddlewares.push(middleware1);
                continue;
            }
            if (layerMiddlewares.length) {
                this.#addLayer(path, layerMiddlewares, methods, options);
                layerMiddlewares = [];
            }
            const router = middleware1.router.#clone();
            for (const layer of router.#stack){
                if (!options.ignorePrefix) {
                    layer.setPrefix(path);
                }
                if (this.#opts.prefix) {
                    layer.setPrefix(this.#opts.prefix);
                }
                this.#stack.push(layer);
            }
            for (const [param, mw] of Object.entries(this.#params)){
                router.param(param, mw);
            }
        }
        if (layerMiddlewares.length) {
            this.#addLayer(path, layerMiddlewares, methods, options);
        }
    }
     #addLayer(path, middlewares, methods, options = {
    }) {
        const { end , name: name3 , sensitive =this.#opts.sensitive , strict =this.#opts.strict , ignoreCaptures ,  } = options;
        const route = new Layer(path, methods, middlewares, {
            end,
            name: name3,
            sensitive,
            strict,
            ignoreCaptures
        });
        if (this.#opts.prefix) {
            route.setPrefix(this.#opts.prefix);
        }
        for (const [param, mw] of Object.entries(this.#params)){
            route.param(param, mw);
        }
        this.#stack.push(route);
    }
     #route(name) {
        for (const route of this.#stack){
            if (route.name === name) {
                return route;
            }
        }
    }
     #useVerb(nameOrPath, pathOrMiddleware, middleware, methods) {
        let name3 = undefined;
        let path3;
        if (typeof pathOrMiddleware === "string") {
            name3 = nameOrPath;
            path3 = pathOrMiddleware;
        } else {
            path3 = nameOrPath;
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path3, middleware, methods, {
            name: name3
        });
    }
     #clone() {
        const router = new Router(this.#opts);
        router.#methods = router.#methods.slice();
        router.#params = {
            ...this.#params
        };
        router.#stack = this.#stack.map((layer)=>layer.clone()
        );
        return router;
    }
    constructor(opts1 = {
    }){
        this.#opts = opts1;
        this.#methods = opts1.methods ?? [
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT", 
        ];
    }
    all(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "DELETE",
            "GET",
            "POST",
            "PUT"
        ]);
        return this;
    }
    allowedMethods(options = {
    }) {
        const implemented = this.#methods;
        const allowedMethods = async (context3, next)=>{
            const ctx = context3;
            await next();
            if (!ctx.response.status || ctx.response.status === Status.NotFound) {
                assert1(ctx.matched);
                const allowed = new Set();
                for (const route of ctx.matched){
                    for (const method of route.methods){
                        allowed.add(method);
                    }
                }
                const allowedStr = [
                    ...allowed
                ].join(", ");
                if (!implemented.includes(ctx.request.method)) {
                    if (options.throw) {
                        throw options.notImplemented ? options.notImplemented() : new httpErrors.NotImplemented();
                    } else {
                        ctx.response.status = Status.NotImplemented;
                        ctx.response.headers.set("Allowed", allowedStr);
                    }
                } else if (allowed.size) {
                    if (ctx.request.method === "OPTIONS") {
                        ctx.response.status = Status.OK;
                        ctx.response.headers.set("Allowed", allowedStr);
                    } else if (!allowed.has(ctx.request.method)) {
                        if (options.throw) {
                            throw options.methodNotAllowed ? options.methodNotAllowed() : new httpErrors.MethodNotAllowed();
                        } else {
                            ctx.response.status = Status.MethodNotAllowed;
                            ctx.response.headers.set("Allowed", allowedStr);
                        }
                    }
                }
            }
        };
        return allowedMethods;
    }
    delete(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "DELETE"
        ]);
        return this;
    }
    *entries() {
        for (const route of this.#stack){
            const value4 = route.toJSON();
            yield [
                value4,
                value4
            ];
        }
    }
    forEach(callback, thisArg = null) {
        for (const route of this.#stack){
            const value4 = route.toJSON();
            callback.call(thisArg, value4, value4, this);
        }
    }
    get(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "GET"
        ]);
        return this;
    }
    head(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "HEAD"
        ]);
        return this;
    }
    *keys() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    options(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "OPTIONS"
        ]);
        return this;
    }
    param(param, middleware) {
        this.#params[param] = middleware;
        for (const route of this.#stack){
            route.param(param, middleware);
        }
        return this;
    }
    patch(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PATCH"
        ]);
        return this;
    }
    post(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "POST"
        ]);
        return this;
    }
    prefix(prefix) {
        prefix = prefix.replace(/\/$/, "");
        this.#opts.prefix = prefix;
        for (const route of this.#stack){
            route.setPrefix(prefix);
        }
        return this;
    }
    put(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PUT"
        ]);
        return this;
    }
    redirect(source, destination, status = Status.Found) {
        if (source[0] !== "/") {
            const s1 = this.url(source);
            if (!s1) {
                throw new RangeError(`Could not resolve named route: "${source}"`);
            }
            source = s1;
        }
        if (typeof destination === "string") {
            if (destination[0] !== "/") {
                const d = this.url(destination);
                if (!d) {
                    try {
                        const url1 = new URL(destination);
                        destination = url1;
                    } catch  {
                        throw new RangeError(`Could not resolve named route: "${source}"`);
                    }
                } else {
                    destination = d;
                }
            }
        }
        this.all(source, async (ctx, next)=>{
            await next();
            ctx.response.redirect(destination);
            ctx.response.status = status;
        });
        return this;
    }
    routes() {
        const dispatch = (context3, next)=>{
            const ctx = context3;
            let pathname;
            let method;
            try {
                const { url: { pathname: p2  } , method: m  } = ctx.request;
                pathname = p2;
                method = m;
            } catch (e) {
                return Promise.reject(e);
            }
            const path3 = (this.#opts.routerPath ?? ctx.routerPath) ?? decodeURIComponent(pathname);
            const matches1 = this.#match(path3, method);
            if (ctx.matched) {
                ctx.matched.push(...matches1.path);
            } else {
                ctx.matched = [
                    ...matches1.path
                ];
            }
            ctx.router = this;
            if (!matches1.route) return next();
            const { pathAndMethod: matchedRoutes  } = matches1;
            const chain = matchedRoutes.reduce((prev, route)=>[
                    ...prev,
                    (ctx1, next1)=>{
                        ctx1.captures = route.captures(path3);
                        ctx1.params = route.params(ctx1.captures, ctx1.params);
                        ctx1.routeName = route.name;
                        return next1();
                    },
                    ...route.stack, 
                ]
            , []);
            return compose(chain)(ctx, next);
        };
        dispatch.router = this;
        return dispatch;
    }
    url(name, params, options) {
        const route = this.#route(name);
        if (route) {
            return route.url(params, options);
        }
    }
    use(pathOrMiddleware, ...middleware) {
        let path3;
        if (typeof pathOrMiddleware === "string" || Array.isArray(pathOrMiddleware)) {
            path3 = pathOrMiddleware;
        } else {
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path3 ?? "(.*)", middleware, [], {
            end: false,
            ignoreCaptures: !path3,
            ignorePrefix: !path3
        });
        return this;
    }
    *values() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    *[Symbol.iterator]() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    static url(path, params, options) {
        return toUrl(path, params, options);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            "#params": this.#params,
            "#stack": this.#stack
        })}`;
    }
}
function bytesToUuid(bytes) {
    const bits = [
        ...bytes
    ].map((bit)=>{
        const s1 = bit.toString(16);
        return bit < 16 ? "0" + s1 : s1;
    });
    return [
        ...bits.slice(0, 4),
        "-",
        ...bits.slice(4, 6),
        "-",
        ...bits.slice(6, 8),
        "-",
        ...bits.slice(8, 10),
        "-",
        ...bits.slice(10, 16), 
    ].join("");
}
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function validate(id1) {
    return UUID_RE.test(id1);
}
function generate() {
    const rnds = crypto.getRandomValues(new Uint8Array(16));
    rnds[6] = rnds[6] & 15 | 64;
    rnds[8] = rnds[8] & 63 | 128;
    return bytesToUuid(rnds);
}
const mod2 = function() {
    return {
        validate: validate,
        generate: generate
    };
}();
const HEX_CHARS2 = "0123456789abcdef".split("");
const EXTRA2 = [
    -2147483648,
    8388608,
    32768,
    128
];
const SHIFT2 = [
    24,
    16,
    8,
    0
];
const blocks2 = [];
class Sha11 {
    #blocks;
    #block;
    #start;
    #bytes;
    #hBytes;
    #finalized;
    #hashed;
    #h0 = 1732584193;
    #h1 = 4023233417;
    #h2 = 2562383102;
    #h3 = 271733878;
    #h4 = 3285377520;
    #lastByteIndex = 0;
    constructor(sharedMemory5 = false){
        this.init(sharedMemory5);
    }
    init(sharedMemory) {
        if (sharedMemory) {
            blocks2[0] = blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
            this.#blocks = blocks2;
        } else {
            this.#blocks = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ];
        }
        this.#h0 = 1732584193;
        this.#h1 = 4023233417;
        this.#h2 = 2562383102;
        this.#h3 = 271733878;
        this.#h4 = 3285377520;
        this.#block = this.#start = this.#bytes = this.#hBytes = 0;
        this.#finalized = this.#hashed = false;
    }
    update(message) {
        if (this.#finalized) {
            return this;
        }
        let msg;
        if (message instanceof ArrayBuffer) {
            msg = new Uint8Array(message);
        } else {
            msg = message;
        }
        let index = 0;
        const length = msg.length;
        const blocks3 = this.#blocks;
        while(index < length){
            let i2;
            if (this.#hashed) {
                this.#hashed = false;
                blocks3[0] = this.#block;
                blocks3[16] = blocks3[1] = blocks3[2] = blocks3[3] = blocks3[4] = blocks3[5] = blocks3[6] = blocks3[7] = blocks3[8] = blocks3[9] = blocks3[10] = blocks3[11] = blocks3[12] = blocks3[13] = blocks3[14] = blocks3[15] = 0;
            }
            if (typeof msg !== "string") {
                for(i2 = this.#start; index < length && i2 < 64; ++index){
                    blocks3[i2 >> 2] |= msg[index] << SHIFT2[(i2++) & 3];
                }
            } else {
                for(i2 = this.#start; index < length && i2 < 64; ++index){
                    let code = msg.charCodeAt(index);
                    if (code < 128) {
                        blocks3[i2 >> 2] |= code << SHIFT2[(i2++) & 3];
                    } else if (code < 2048) {
                        blocks3[i2 >> 2] |= (192 | code >> 6) << SHIFT2[(i2++) & 3];
                        blocks3[i2 >> 2] |= (128 | code & 63) << SHIFT2[(i2++) & 3];
                    } else if (code < 55296 || code >= 57344) {
                        blocks3[i2 >> 2] |= (224 | code >> 12) << SHIFT2[(i2++) & 3];
                        blocks3[i2 >> 2] |= (128 | code >> 6 & 63) << SHIFT2[(i2++) & 3];
                        blocks3[i2 >> 2] |= (128 | code & 63) << SHIFT2[(i2++) & 3];
                    } else {
                        code = 65536 + ((code & 1023) << 10 | msg.charCodeAt(++index) & 1023);
                        blocks3[i2 >> 2] |= (240 | code >> 18) << SHIFT2[(i2++) & 3];
                        blocks3[i2 >> 2] |= (128 | code >> 12 & 63) << SHIFT2[(i2++) & 3];
                        blocks3[i2 >> 2] |= (128 | code >> 6 & 63) << SHIFT2[(i2++) & 3];
                        blocks3[i2 >> 2] |= (128 | code & 63) << SHIFT2[(i2++) & 3];
                    }
                }
            }
            this.#lastByteIndex = i2;
            this.#bytes += i2 - this.#start;
            if (i2 >= 64) {
                this.#block = blocks3[16];
                this.#start = i2 - 64;
                this.hash();
                this.#hashed = true;
            } else {
                this.#start = i2;
            }
        }
        if (this.#bytes > 4294967295) {
            this.#hBytes += this.#bytes / 4294967296 >>> 0;
            this.#bytes = this.#bytes >>> 0;
        }
        return this;
    }
    finalize() {
        if (this.#finalized) {
            return;
        }
        this.#finalized = true;
        const blocks3 = this.#blocks;
        const i2 = this.#lastByteIndex;
        blocks3[16] = this.#block;
        blocks3[i2 >> 2] |= EXTRA2[i2 & 3];
        this.#block = blocks3[16];
        if (i2 >= 56) {
            if (!this.#hashed) {
                this.hash();
            }
            blocks3[0] = this.#block;
            blocks3[16] = blocks3[1] = blocks3[2] = blocks3[3] = blocks3[4] = blocks3[5] = blocks3[6] = blocks3[7] = blocks3[8] = blocks3[9] = blocks3[10] = blocks3[11] = blocks3[12] = blocks3[13] = blocks3[14] = blocks3[15] = 0;
        }
        blocks3[14] = this.#hBytes << 3 | this.#bytes >>> 29;
        blocks3[15] = this.#bytes << 3;
        this.hash();
    }
    hash() {
        let a = this.#h0;
        let b = this.#h1;
        let c = this.#h2;
        let d = this.#h3;
        let e = this.#h4;
        let f;
        let j;
        let t;
        const blocks3 = this.#blocks;
        for(j = 16; j < 80; ++j){
            t = blocks3[j - 3] ^ blocks3[j - 8] ^ blocks3[j - 14] ^ blocks3[j - 16];
            blocks3[j] = t << 1 | t >>> 31;
        }
        for(j = 0; j < 20; j += 5){
            f = b & c | ~b & d;
            t = a << 5 | a >>> 27;
            e = t + f + e + 1518500249 + blocks3[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a & b | ~a & c;
            t = e << 5 | e >>> 27;
            d = t + f + d + 1518500249 + blocks3[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e & a | ~e & b;
            t = d << 5 | d >>> 27;
            c = t + f + c + 1518500249 + blocks3[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d & e | ~d & a;
            t = c << 5 | c >>> 27;
            b = t + f + b + 1518500249 + blocks3[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c & d | ~c & e;
            t = b << 5 | b >>> 27;
            a = t + f + a + 1518500249 + blocks3[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 40; j += 5){
            f = b ^ c ^ d;
            t = a << 5 | a >>> 27;
            e = t + f + e + 1859775393 + blocks3[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a ^ b ^ c;
            t = e << 5 | e >>> 27;
            d = t + f + d + 1859775393 + blocks3[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e ^ a ^ b;
            t = d << 5 | d >>> 27;
            c = t + f + c + 1859775393 + blocks3[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d ^ e ^ a;
            t = c << 5 | c >>> 27;
            b = t + f + b + 1859775393 + blocks3[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c ^ d ^ e;
            t = b << 5 | b >>> 27;
            a = t + f + a + 1859775393 + blocks3[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 60; j += 5){
            f = b & c | b & d | c & d;
            t = a << 5 | a >>> 27;
            e = t + f + e - 1894007588 + blocks3[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a & b | a & c | b & c;
            t = e << 5 | e >>> 27;
            d = t + f + d - 1894007588 + blocks3[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e & a | e & b | a & b;
            t = d << 5 | d >>> 27;
            c = t + f + c - 1894007588 + blocks3[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d & e | d & a | e & a;
            t = c << 5 | c >>> 27;
            b = t + f + b - 1894007588 + blocks3[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c & d | c & e | d & e;
            t = b << 5 | b >>> 27;
            a = t + f + a - 1894007588 + blocks3[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 80; j += 5){
            f = b ^ c ^ d;
            t = a << 5 | a >>> 27;
            e = t + f + e - 899497514 + blocks3[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a ^ b ^ c;
            t = e << 5 | e >>> 27;
            d = t + f + d - 899497514 + blocks3[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e ^ a ^ b;
            t = d << 5 | d >>> 27;
            c = t + f + c - 899497514 + blocks3[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d ^ e ^ a;
            t = c << 5 | c >>> 27;
            b = t + f + b - 899497514 + blocks3[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c ^ d ^ e;
            t = b << 5 | b >>> 27;
            a = t + f + a - 899497514 + blocks3[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        this.#h0 = this.#h0 + a >>> 0;
        this.#h1 = this.#h1 + b >>> 0;
        this.#h2 = this.#h2 + c >>> 0;
        this.#h3 = this.#h3 + d >>> 0;
        this.#h4 = this.#h4 + e >>> 0;
    }
    hex() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        return HEX_CHARS2[h0 >> 28 & 15] + HEX_CHARS2[h0 >> 24 & 15] + HEX_CHARS2[h0 >> 20 & 15] + HEX_CHARS2[h0 >> 16 & 15] + HEX_CHARS2[h0 >> 12 & 15] + HEX_CHARS2[h0 >> 8 & 15] + HEX_CHARS2[h0 >> 4 & 15] + HEX_CHARS2[h0 & 15] + HEX_CHARS2[h1 >> 28 & 15] + HEX_CHARS2[h1 >> 24 & 15] + HEX_CHARS2[h1 >> 20 & 15] + HEX_CHARS2[h1 >> 16 & 15] + HEX_CHARS2[h1 >> 12 & 15] + HEX_CHARS2[h1 >> 8 & 15] + HEX_CHARS2[h1 >> 4 & 15] + HEX_CHARS2[h1 & 15] + HEX_CHARS2[h2 >> 28 & 15] + HEX_CHARS2[h2 >> 24 & 15] + HEX_CHARS2[h2 >> 20 & 15] + HEX_CHARS2[h2 >> 16 & 15] + HEX_CHARS2[h2 >> 12 & 15] + HEX_CHARS2[h2 >> 8 & 15] + HEX_CHARS2[h2 >> 4 & 15] + HEX_CHARS2[h2 & 15] + HEX_CHARS2[h3 >> 28 & 15] + HEX_CHARS2[h3 >> 24 & 15] + HEX_CHARS2[h3 >> 20 & 15] + HEX_CHARS2[h3 >> 16 & 15] + HEX_CHARS2[h3 >> 12 & 15] + HEX_CHARS2[h3 >> 8 & 15] + HEX_CHARS2[h3 >> 4 & 15] + HEX_CHARS2[h3 & 15] + HEX_CHARS2[h4 >> 28 & 15] + HEX_CHARS2[h4 >> 24 & 15] + HEX_CHARS2[h4 >> 20 & 15] + HEX_CHARS2[h4 >> 16 & 15] + HEX_CHARS2[h4 >> 12 & 15] + HEX_CHARS2[h4 >> 8 & 15] + HEX_CHARS2[h4 >> 4 & 15] + HEX_CHARS2[h4 & 15];
    }
    toString() {
        return this.hex();
    }
    digest() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        return [
            h0 >> 24 & 255,
            h0 >> 16 & 255,
            h0 >> 8 & 255,
            h0 & 255,
            h1 >> 24 & 255,
            h1 >> 16 & 255,
            h1 >> 8 & 255,
            h1 & 255,
            h2 >> 24 & 255,
            h2 >> 16 & 255,
            h2 >> 8 & 255,
            h2 & 255,
            h3 >> 24 & 255,
            h3 >> 16 & 255,
            h3 >> 8 & 255,
            h3 & 255,
            h4 >> 24 & 255,
            h4 >> 16 & 255,
            h4 >> 8 & 255,
            h4 & 255, 
        ];
    }
    array() {
        return this.digest();
    }
    arrayBuffer() {
        this.finalize();
        const buffer = new ArrayBuffer(20);
        const dataView = new DataView(buffer);
        dataView.setUint32(0, this.#h0);
        dataView.setUint32(4, this.#h1);
        dataView.setUint32(8, this.#h2);
        dataView.setUint32(12, this.#h3);
        dataView.setUint32(16, this.#h4);
        return buffer;
    }
}
class HmacSha11 extends Sha11 {
    #sharedMemory;
    #inner;
    #oKeyPad;
    constructor(secretKey2, sharedMemory6 = false){
        super(sharedMemory6);
        let key5;
        if (typeof secretKey2 === "string") {
            const bytes = [];
            const length = secretKey2.length;
            let index = 0;
            for(let i2 = 0; i2 < length; i2++){
                let code = secretKey2.charCodeAt(i2);
                if (code < 128) {
                    bytes[index++] = code;
                } else if (code < 2048) {
                    bytes[index++] = 192 | code >> 6;
                    bytes[index++] = 128 | code & 63;
                } else if (code < 55296 || code >= 57344) {
                    bytes[index++] = 224 | code >> 12;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                } else {
                    code = 65536 + ((code & 1023) << 10 | secretKey2.charCodeAt(++i2) & 1023);
                    bytes[index++] = 240 | code >> 18;
                    bytes[index++] = 128 | code >> 12 & 63;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                }
            }
            key5 = bytes;
        } else {
            if (secretKey2 instanceof ArrayBuffer) {
                key5 = new Uint8Array(secretKey2);
            } else {
                key5 = secretKey2;
            }
        }
        if (key5.length > 64) {
            key5 = new Sha11(true).update(key5).array();
        }
        const oKeyPad2 = [];
        const iKeyPad2 = [];
        for(let i2 = 0; i2 < 64; i2++){
            const b = key5[i2] || 0;
            oKeyPad2[i2] = 92 ^ b;
            iKeyPad2[i2] = 54 ^ b;
        }
        this.update(iKeyPad2);
        this.#oKeyPad = oKeyPad2;
        this.#inner = true;
        this.#sharedMemory = sharedMemory6;
    }
    finalize() {
        super.finalize();
        if (this.#inner) {
            this.#inner = false;
            const innerHash = this.array();
            super.init(this.#sharedMemory);
            this.update(this.#oKeyPad);
            this.update(innerHash);
            super.finalize();
        }
    }
}
class DenoStdInternalError1 extends Error {
    constructor(message3){
        super(message3);
        this.name = "DenoStdInternalError";
    }
}
let products = [
    {
        id: "1",
        name: "Product 1",
        description: "This first product",
        price: 30
    },
    {
        id: "2",
        name: "Product 2",
        description: "This second product",
        price: 40
    },
    {
        id: "3",
        name: "Product 3",
        description: "This third product",
        price: 50
    },
    {
        id: "4",
        name: "Product 4",
        description: "This fourth product",
        price: 60
    }, 
];
const getProducts = ({ response: response3  })=>{
    response3.body = {
        success: true,
        data: products
    };
};
const addProducts = async ({ request: request4 , response: response3  })=>{
    const body1 = await request4.body();
    if (!request4.hasBody) {
        response3.body = {
            success: true,
            msg: "No data!"
        };
    } else {
        let product = await body1.value;
        product.id = mod2.generate();
        products.push(product);
        response3.body = {
            success: true,
            data: product
        };
    }
};
const router = new Router();
router.get("/api/products", getProducts);
router.post("/api/products", addProducts);
const app3 = new Application();
app3.use(router.routes());
app3.use(router.allowedMethods());
console.log(`Server on port ${5000}`);
app3.listen({
    port: 5000
});

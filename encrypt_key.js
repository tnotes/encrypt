// (c) Copyright 2018 Micro Focus or one of its affiliates.
const request = require('request-promise');
var SDW = {};
SDW.base10 = "0123456789";
SDW.base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
let get_PIE = async ()=>{
	let options = {
		url:'https://pie-production.walgreens.com/pie/v1/Walgreens/getkey.js',
		method:'GET',
		headers:{
			'user-agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36 OPR/67.0.3575.79'
		}
	};
	let responseHTML = await request(options);
	
	let L =  parseInt(responseHTML.match(new RegExp('(?<='+'PIE.L = '+'+).*?(?='+';'+')',"gs"))[0]);
	let E = parseInt(responseHTML.match(new RegExp('(?<='+'PIE.E = '+'+).*?(?='+';'+')',"gs"))[0]);
	let K = responseHTML.match(new RegExp('(?<='+'PIE.K = "'+'+).*?(?='+'"'+')',"gs"))[0];
	let key_id = responseHTML.match(new RegExp('(?<='+'PIE.key_id = "'+'+).*?(?='+'"'+')',"gs"))[0];
	let phase = parseInt(responseHTML.match(new RegExp('(?<='+'PIE.phase = '+'+).*?(?='+';'+')',"gs"))[0]);
	return {L,E,K,key_id,phase};
}
SDW.luhn = function(a) {
    var e = a.length - 1;
    var b = 0;
    while (e >= 0) {
        b += parseInt(a.substr(e, 1), 10);
        e -= 2
    }
    e = a.length - 2;
    while (e >= 0) {
        var c = 2 * parseInt(a.substr(e, 1), 10);
        if (c < 10) {
            b += c
        } else {
            b += c - 9
        }
        e -= 2
    }
    return b % 10
};
SDW.fixluhn = function(b, d, c) {
    var a = SDW.luhn(b);
    if (a < c) {
        a += 10 - c
    } else {
        a -= c
    }
    if (a != 0) {
        if ((b.length - d) % 2 != 0) {
            a = 10 - a
        } else {
            if (a % 2 == 0) {
                a = 5 - (a / 2)
            } else {
                a = (9 - a) / 2 + 5
            }
        }
        return b.substr(0, d) + a + b.substr(d + 1)
    } else {
        return b
    }
};
SDW.distill = function(b) {
    var c = "";
    for (var a = 0; a < b.length; ++a) {
        if (SDW.base10.indexOf(b.charAt(a)) >= 0) {
            c += b.substr(a, 1)
        }
    }
    return c
};
SDW.reformat = function(d, c) {
    var e = "";
    var a = 0;
    for (var b = 0; b < c.length; ++b) {
        if (a < d.length && SDW.base10.indexOf(c.charAt(b)) >= 0) {
            e += d.substr(a, 1);
            ++a
        } else {
            e += c.substr(b, 1)
        }
    }
    return e
};
SDW.integrity = function(a, e, c) {
    var b = String.fromCharCode(0) + String.fromCharCode(e.length) + e + String.fromCharCode(0) + String.fromCharCode(c.length) + c;
    var d = AES.HexToWords(a);
    d[3] ^= 1;
    var f = new sjcl.cipher.aes(d);
    var g = CMAC.compute(f, b);
    return AES.WordToHex(g[0]) + AES.WordToHex(g[1])
};

function ProtectPANandCVV(t, o, k,PIE) {
    var l = SDW.distill(t);
    var r = SDW.distill(o);
    if (l.length < 13 || l.length > 19 || r.length > 4 || r.length == 1 || r.length == 2) {
        return null
    }
    var g = l.substr(0, PIE.L) + l.substring(l.length - PIE.E);
    if (k == true) {
        var p = SDW.luhn(l);
        var j = l.substring(PIE.L + 1, l.length - PIE.E);
        var f = FFX.encrypt(j + r, g, PIE.K, 10);
        var b = l.substr(0, PIE.L) + "0" + f.substr(0, f.length - r.length) + l.substring(l.length - PIE.E);
        var s = SDW.reformat(SDW.fixluhn(b, PIE.L, p), t);
        var q = SDW.reformat(f.substring(f.length - r.length), o);
        return [s, q, SDW.integrity(PIE.K, s, q)]
    }
    if (SDW.luhn(l) != 0) {
        return null
    }
    var j = l.substring(PIE.L + 1, l.length - PIE.E);
    var v = 23 - PIE.L - PIE.E;
    var h = j + r;
    var u = Math.floor((v * Math.log(62) - 34 * Math.log(2)) / Math.log(10)) - h.length - 1;
    var x = "11111111111111111111111111111".substr(0, u) + (2 * r.length);
    var f = "1" + FFX.encrypt(x + h, g, PIE.K, 10);
    var e = parseInt(PIE.key_id, 16);
    var a = new Array(f.length);
    var w;
    for (w = 0; w < f.length; ++w) {
        a[w] = parseInt(f.substr(w, 1), 10)
    }
    var d = FFX.convertRadix(a, f.length, 10, v, 62);
    FFX.bnMultiply(d, 62, 131072);
    FFX.bnMultiply(d, 62, 65536);
    FFX.bnAdd(d, 62, e);
    if (PIE.phase == 1) {
        FFX.bnAdd(d, 62, 4294967296)
    }
    var c = "";
    for (w = 0; w < v; ++w) {
        c = c + SDW.base62.substr(d[w], 1)
    }
    var s = l.substr(0, PIE.L) + c.substr(0, v - 4) + l.substring(l.length - PIE.E);
    var q = c.substring(v - 4);
    return [s, q, SDW.integrity(PIE.K, s, q)]
}

function ValidatePANChecksum(b) {
    var a = SDW.distill(b);
    return (a.length >= 13 && a.length <= 19 && SDW.luhn(a) == 0)
}

function ProtectString(g, h,PIE) {
    var f = SDW_UTF8.encode(g);
    if (f.length < 2 || f.length > 256) {
        return null
    }
    var b;
    if (h == null) {
        b = ""
    } else {
        b = SDW_UTF8.encode(h);
        if (b.length > 256) {
            return null
        }
    }
    var c = AES.HexToWords(PIE.K);
    c[3] ^= 2;
    var e = new sjcl.cipher.aes(c);
    var a = FFX.encryptWithCipher(f, b, e, 256);
    var d = SDW_Base64.encode(a);
    return [d]
}
"use strict";
var sjcl = {
    cipher: {},
    hash: {},
    mode: {},
    misc: {},
    codec: {},
    exception: {
        corrupt: function(a) {
            this.toString = function() {
                return "CORRUPT: " + this.message
            };
            this.message = a
        },
        invalid: function(a) {
            this.toString = function() {
                return "INVALID: " + this.message
            };
            this.message = a
        },
        bug: function(a) {
            this.toString = function() {
                return "BUG: " + this.message
            };
            this.message = a
        }
    }
};
sjcl.cipher.aes = function(h) {
    if (!this._tables[0][0][0]) {
        this._precompute()
    }
    var d, c, e, g, l, f = this._tables[0][4],
        k = this._tables[1],
        a = h.length,
        b = 1;
    if (a !== 4 && a !== 6 && a !== 8) {
        throw new sjcl.exception.invalid("invalid aes key size")
    }
    this._key = [g = h.slice(0), l = []];
    for (d = a; d < 4 * a + 28; d++) {
        e = g[d - 1];
        if (d % a === 0 || (a === 8 && d % a === 4)) {
            e = f[e >>> 24] << 24 ^ f[e >> 16 & 255] << 16 ^ f[e >> 8 & 255] << 8 ^ f[e & 255];
            if (d % a === 0) {
                e = e << 8 ^ e >>> 24 ^ b << 24;
                b = b << 1 ^ (b >> 7) * 283
            }
        }
        g[d] = g[d - a] ^ e
    }
    for (c = 0; d; c++, d--) {
        e = g[c & 3 ? d : d - 4];
        if (d <= 4 || c < 4) {
            l[c] = e
        } else {
            l[c] = k[0][f[e >>> 24]] ^ k[1][f[e >> 16 & 255]] ^ k[2][f[e >> 8 & 255]] ^ k[3][f[e & 255]]
        }
    }
};
sjcl.cipher.aes.prototype = {
    encrypt: function(a) {
        return this._crypt(a, 0)
    },
    decrypt: function(a) {
        return this._crypt(a, 1)
    },
    _tables: [
        [
            [],
            [],
            [],
            [],
            []
        ],
        [
            [],
            [],
            [],
            [],
            []
        ]
    ],
    _precompute: function() {
        var j = this._tables[0],
            q = this._tables[1],
            h = j[4],
            n = q[4],
            g, l, f, k = [],
            c = [],
            b, p, m, o, e, a;
        for (g = 0; g < 256; g++) {
            c[(k[g] = g << 1 ^ (g >> 7) * 283) ^ g] = g
        }
        for (l = f = 0; !h[l]; l ^= (b == 0) ? 1 : b, f = (c[f] == 0) ? 1 : c[f]) {
            o = f ^ f << 1 ^ f << 2 ^ f << 3 ^ f << 4;
            o = o >> 8 ^ o & 255 ^ 99;
            h[l] = o;
            n[o] = l;
            m = k[p = k[b = k[l]]];
            a = m * 16843009 ^ p * 65537 ^ b * 257 ^ l * 16843008;
            e = k[o] * 257 ^ o * 16843008;
            for (g = 0; g < 4; g++) {
                j[g][l] = e = e << 24 ^ e >>> 8;
                q[g][o] = a = a << 24 ^ a >>> 8
            }
        }
        for (g = 0; g < 5; g++) {
            j[g] = j[g].slice(0);
            q[g] = q[g].slice(0)
        }
    },
    _crypt: function(k, n) {
        if (k.length !== 4) {
            throw new sjcl.exception.invalid("invalid aes block size")
        }
        var y = this._key[n],
            v = k[0] ^ y[0],
            u = k[n ? 3 : 1] ^ y[1],
            t = k[2] ^ y[2],
            s = k[n ? 1 : 3] ^ y[3],
            w, e, m, x = y.length / 4 - 2,
            p, o = 4,
            q = [0, 0, 0, 0],
            r = this._tables[n],
            j = r[0],
            h = r[1],
            g = r[2],
            f = r[3],
            l = r[4];
        for (p = 0; p < x; p++) {
            w = j[v >>> 24] ^ h[u >> 16 & 255] ^ g[t >> 8 & 255] ^ f[s & 255] ^ y[o];
            e = j[u >>> 24] ^ h[t >> 16 & 255] ^ g[s >> 8 & 255] ^ f[v & 255] ^ y[o + 1];
            m = j[t >>> 24] ^ h[s >> 16 & 255] ^ g[v >> 8 & 255] ^ f[u & 255] ^ y[o + 2];
            s = j[s >>> 24] ^ h[v >> 16 & 255] ^ g[u >> 8 & 255] ^ f[t & 255] ^ y[o + 3];
            o += 4;
            v = w;
            u = e;
            t = m
        }
        for (p = 0; p < 4; p++) {
            q[n ? 3 & -p : p] = l[v >>> 24] << 24 ^ l[u >> 16 & 255] << 16 ^ l[t >> 8 & 255] << 8 ^ l[s & 255] ^ y[o++];
            w = v;
            v = u;
            u = t;
            t = s;
            s = w
        }
        return q
    }
};
var AES = {};
AES.HexToKey = function(a) {
    return new sjcl.cipher.aes(AES.HexToWords(a))
};
AES.HexToWords = function(a) {
    var d = 4;
    var c = new Array(d);
    if (a.length != d * 8) {
        return null
    }
    for (var b = 0; b < d; b++) {
        c[b] = parseInt(a.substr(b * 8, 8), 16)
    }
    return c
};
AES.Hex = "0123456789abcdef";
AES.WordToHex = function(a) {
    var c = 32;
    var b = "";
    while (c > 0) {
        c -= 4;
        b += AES.Hex.substr((a >>> c) & 15, 1)
    }
    return b
};
var SDW_Base64 = {
    _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    encode: function(d) {
        var b = 0;
        var e = "";
        var f, a;
        while (b < d.length) {
            f = d.charCodeAt(b) & 255;
            e += SDW_Base64._chars.charAt(f >> 2);
            a = (f & 3) << 4;
            if (++b < d.length) {
                f = d.charCodeAt(b) & 255;
                a |= f >> 4
            }
            e += SDW_Base64._chars.charAt(a);
            if (b >= d.length) {
                break
            }
            a = (f & 15) << 2;
            if (++b < d.length) {
                f = d.charCodeAt(b) & 255;
                a |= f >> 6
            }
            e += SDW_Base64._chars.charAt(a);
            if (b >= d.length) {
                break
            }
            e += SDW_Base64._chars.charAt(f & 63);
            ++b
        }
        return e
    }
};
var SDW_UTF8 = {
    encode: function(b) {
        var d = "";
        var a = 0;
        while (a < b.length) {
            var e = b.charCodeAt(a);
            if (e < 128) {
                d += String.fromCharCode(e)
            } else {
                if (e >= 2048) {
                    d += String.fromCharCode((e >> 12) | 224) + String.fromCharCode(((e >> 6) & 63) | 128) + String.fromCharCode((e & 63) | 128)
                } else {
                    d += String.fromCharCode((e >> 6) | 192) + String.fromCharCode((e & 63) | 128)
                }
            }++a
        }
        return d
    }
};
var CMAC = {};
CMAC.MSBnotZero = function(a) {
    if ((a | 2147483647) == 2147483647) {
        return false
    } else {
        return true
    }
};
CMAC.leftShift = function(b) {
    b[0] = ((b[0] & 2147483647) << 1) | (b[1] >>> 31);
    b[1] = ((b[1] & 2147483647) << 1) | (b[2] >>> 31);
    b[2] = ((b[2] & 2147483647) << 1) | (b[3] >>> 31);
    b[3] = ((b[3] & 2147483647) << 1)
};
CMAC.const_Rb = 135;
CMAC.compute = function(a, d) {
    var f = [0, 0, 0, 0];
    var b = a.encrypt(f);
    var c = b[0];
    CMAC.leftShift(b);
    if (CMAC.MSBnotZero(c)) {
        b[3] ^= CMAC.const_Rb
    }
    var e = 0;
    while (e < d.length) {
        f[(e >> 2) & 3] ^= (d.charCodeAt(e) & 255) << (8 * (3 - (e & 3)));
        ++e;
        if ((e & 15) == 0 && e < d.length) {
            f = a.encrypt(f)
        }
    }
    if (e == 0 || (e & 15) != 0) {
        c = b[0];
        CMAC.leftShift(b);
        if (CMAC.MSBnotZero(c)) {
            b[3] ^= CMAC.const_Rb
        }
        f[(e >> 2) & 3] ^= 128 << (8 * (3 - (e & 3)))
    }
    f[0] ^= b[0];
    f[1] ^= b[1];
    f[2] ^= b[2];
    f[3] ^= b[3];
    return a.encrypt(f)
};

function CMAC_AES128(b, a) {
    return CMAC.compute(AES.HexToKey(b), a)
}
var FFX = {};
FFX.alphabet = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"];
FFX.precompF = function(a, h, g, e) {
    var d = 4;
    var f = new Array(d);
    var c = g.length;
    var b = 10;
    f[0] = 16908544 | ((e >> 16) & 255);
    f[1] = (((e >> 8) & 255) << 24) | ((e & 255) << 16) | (b << 8) | (Math.floor(h / 2) & 255);
    f[2] = h;
    f[3] = c;
    return a.encrypt(f)
};
FFX.precompb = function(c, g) {
    var e = Math.ceil(g / 2);
    var a = 0;
    var d = 1;
    while (e > 0) {
        d = d * c;
        --e;
        if (d >= 256) {
            d = d / 256;
            ++a
        }
    }
    if (d > 1) {
        ++a
    }
    return a
};
FFX.bnMultiply = function(b, d, g) {
    var c;
    var e = 0;
    for (c = b.length - 1; c >= 0; --c) {
        var f = b[c] * g + e;
        b[c] = f % d;
        e = (f - b[c]) / d
    }
};
FFX.bnAdd = function(b, d, g) {
    var c = b.length - 1;
    var e = g;
    while (c >= 0 && e > 0) {
        var f = b[c] + e;
        b[c] = f % d;
        e = (f - b[c]) / d;
        --c
    }
};
FFX.convertRadix = function(f, g, e, d, h) {
    var a = new Array(d);
    var c;
    for (c = 0; c < d; ++c) {
        a[c] = 0
    }
    for (var b = 0; b < g; ++b) {
        FFX.bnMultiply(a, h, e);
        FFX.bnAdd(a, h, f[b])
    }
    return a
};
FFX.cbcmacq = function(e, f, b, a) {
    var d = 4;
    var h = new Array(d);
    for (var c = 0; c < d; ++c) {
        h[c] = e[c]
    }
    var g = 0;
    while (4 * g < b) {
        for (var c = 0; c < d; ++c) {
            h[c] = h[c] ^ ((f[4 * (g + c)] << 24) | (f[4 * (g + c) + 1] << 16) | (f[4 * (g + c) + 2] << 8) | f[4 * (g + c) + 3])
        }
        h = a.encrypt(h);
        g = g + d
    }
    return h
};
FFX.F = function(c, u, w, o, g, x, a, l, v) {
    var m = 16;
    var t = Math.ceil(v / 4) + 1;
    var p = (w.length + v + 1) & 15;
    if (p > 0) {
        p = 16 - p
    }
    var k = new Array(w.length + p + v + 1);
    var s;
    for (s = 0; s < w.length; s++) {
        k[s] = w.charCodeAt(s)
    }
    for (; s < p + w.length; s++) {
        k[s] = 0
    }
    k[k.length - v - 1] = u;
    var h = FFX.convertRadix(o, g, l, v, 256);
    for (var q = 0; q < v; q++) {
        k[k.length - v + q] = h[q]
    }
    var e = FFX.cbcmacq(a, k, k.length, c);
    var n = e;
    var r;
    var f = new Array(2 * t);
    for (s = 0; s < t; ++s) {
        if (s > 0 && (s & 3) == 0) {
            r = s >> 2;
            n = c.encrypt([e[0], e[1], e[2], e[3] ^ r])
        }
        f[2 * s] = n[s & 3] >>> 16;
        f[2 * s + 1] = n[s & 3] & 65535
    }
    return FFX.convertRadix(f, 2 * t, 65536, x, l)
};
FFX.DigitToVal = function(c, a, e) {
    var f = new Array(a);
    if (e == 256) {
        for (var b = 0; b < a; b++) {
            f[b] = c.charCodeAt(b)
        }
        return f
    }
    for (var d = 0; d < a; d++) {
        var g = parseInt(c.charAt(d), e);
        if ((g == NaN) || !(g < e)) {
            return ""
        }
        f[d] = g
    }
    return f
};
FFX.ValToDigit = function(d, c) {
    var a = "";
    var b;
    if (c == 256) {
        for (b = 0; b < d.length; b++) {
            a += String.fromCharCode(d[b])
        }
    } else {
        for (b = 0; b < d.length; b++) {
            a += FFX.alphabet[d[b]]
        }
    }
    return a
};
FFX.encryptWithCipher = function(d, m, p, s) {
    var f = d.length;
    var g = Math.floor(f / 2);
    var a = 5;
    var t = FFX.precompF(p, f, m, s);
    var q = FFX.precompb(s, f);
    var e = FFX.DigitToVal(d, g, s);
    var c = FFX.DigitToVal(d.substr(g), (f - g), s);
    if ((e == "") || (c == "")) {
        return ""
    }
    for (var k = 0; k < a; k++) {
        var v;
        var u = FFX.F(p, k * 2, m, c, c.length, e.length, t, s, q);
        v = 0;
        for (var h = e.length - 1; h >= 0; --h) {
            var o = e[h] + u[h] + v;
            if (o < s) {
                e[h] = o;
                v = 0
            } else {
                e[h] = o - s;
                v = 1
            }
        }
        var u = FFX.F(p, (k * 2) + 1, m, e, e.length, c.length, t, s, q);
        v = 0;
        for (var h = c.length - 1; h >= 0; --h) {
            var o = c[h] + u[h] + v;
            if (o < s) {
                c[h] = o;
                v = 0
            } else {
                c[h] = o - s;
                v = 1
            }
        }
    }
    return FFX.ValToDigit(e, s) + FFX.ValToDigit(c, s)
};
FFX.encrypt = function(d, e, b, c) {
    var a = AES.HexToKey(b);
    if (a == null) {
        return ""
    }
    return FFX.encryptWithCipher(d, e, a, c)
};







var SP_Multiple_CrdeitcardsException = false;
var Sp_Exception_Count = 0;
var IsCrdeitCardValid = false;
var CCType = "";
var ImagURL = "";
var CCFourDigit = "";
var CCExpiry = "";
var current_CreditCardUpdation = "";
var current_Status_toggle = "";
var Sp_credit_card_len = 0;
var tableRowIndex = 0;
var ccTokenKey = "";




function Specialty_changeCardImage(value) {
      var cardType = getCardType(value);
      let type;
      if(cardType.cardType === "masterCard"){
            type = "mastercard";
      }else if(cardType.cardType === "americanExpress"){
            type = "amex";
      }else{
            type = cardType.cardType;
      }
    $(".Sp-payments-credit-cards .wag-cc-icons-img").hide(); 
    if (type === "discover" || type === "visa" || type === "mastercard" || type === "amex") {
        $("." + type).show();
        $("." + type).removeClass('hide');
        ImagURL = "/images/adaptive/share/images/lsg/cc-icon-" + type + ".gif";
        CCType = type;
        $('#credit_card_value').parent('.input__contain').removeClass('input__error');
    }
}



function showModal() {
    $("#paypal-Seeterms").addClass('show-modal');
    if(orderTenderResponse.tenderWidgetInfo.sourceSite === "dotcom"){
      handleModalFocus('paypalSeeTerms');
    }
}
function hideModal() {
    $("#paypal-Seeterms").removeClass('show-modal');
    document.getElementById("paypalSeeTermsLink").focus();
}
function hideLoading() {
    $(".wag-hide-loading").css("display", "none")
}
function getNumber(string) {
    return string.replace(/[^\d]/g, "");
}
var encrypetedCardNo = "";
var subfid9B = "";
async function volatageCard(ccNumber) {
    ccNumber = ccNumber.replace(/ +/g, "");
    this.returnValue = '';
    var voltageOutput = await getEncryptionValue(ccNumber);
    if (voltageOutput && voltageOutput === "Invalid") {
        console.log("Invalid");
        console.log("We're unable to process your request at this time. Please try again.");
        var returnValue = "Invalid";
    } else if (voltageOutput && voltageOutput === "Error") {
        console.log("Error");
        console.log("We're unable to process your request at this time. Please try again.");
        returnValue = "Error";
    } else {
        encrypetedCardNo = voltageOutput.encrypttedCardNumResult;
        subfid9B = voltageOutput.subfid9B;
        console.log("Success");
        returnValue = "Success";
    }
    return returnValue;
}

var tryMore = 10;
function loadVoltScript() {
    $.when(
        $.getScript(config.voltage.getKeyUrl),
        $.getScript(config.voltage.encryptionUrl),
        $.Deferred(function (deferred) {
            $(deferred.resolve);
        })
    ).then(function(){
      console.log("then")
    }).done(function(){
        if (is_pie_key_download_error() || is_pie_encryption_download_error()) {
              loadVoltScript();
          }
          else{
              console.log('success');
          }
    }).fail(function () {
        if (tryMore !== 0) {
            tryMore = tryMore - 1;
            console.log("failed " + tryMore);
            loadVoltScript();
        }
    });
}

// This function checks whether getkey.js is loaded.
function is_pie_key_download_error() {
    // If these PIE variables are not defined, then the required
    // getkey.js include failed.
    if ((typeof (PIE) == 'undefined')
        || (typeof (PIE.K) == 'undefined')
        || (typeof (PIE.L) == 'undefined')
        || (typeof (PIE.E) == 'undefined')
        || (typeof (PIE.key_id) == 'undefined')
        || (typeof (PIE.phase) == 'undefined')) {
        return true;
    }
    return false;
}

// This function checks whether encryption.js is loaded.
function is_pie_encryption_download_error() {
    // If this function is not defined, then the
    // required encryption.js include failed.
    if ((typeof ValidatePANChecksum != 'function')
        || (typeof ProtectPANandCVV != 'function')
        || (typeof ProtectString != 'function')) {
        return true;
    }
    return false;
}
async function getEncryptionValue(value) {
	        let PIE = await get_PIE();

            var card = ProtectPANandCVV(value, '', true,PIE);

            var BA_byte1_dataType;
            var BA_byte2_encryptType;
            var tag_BA;
            var BB_byte1_prfxMetaDataInd;
            var tag_BB;
            var BC_subtagC2_pieType;
            var BC_subtagC3_KeyId;
            var BC_subtagC4_phaseBit;
            var BC_subtagC5_intgCheckVal;
            var BC_subtagC6_implVersNum;
            var tag_BC;
            var tag_BC_substring;
            var subfid9B;
            BA_byte1_dataType = "2"; // 2: Encrypted
            BA_byte2_encryptType = "1"; // 1: Pie Encryption
            BB_byte1_prfxMetaDataInd = "1"; // 0 : Do not sent prefix metadata
            tag_BA = "BA002" + BA_byte1_dataType + BA_byte2_encryptType;
            tag_BB = "BB001" + BB_byte1_prfxMetaDataInd;
            BC_subtagC2_pieType = "C2001" + "3";
            BC_subtagC3_KeyId = "C3" + setLength(PIE.key_id) + PIE.key_id;
            BC_subtagC4_phaseBit = "C4001" + PIE.phase;
            BC_subtagC5_intgCheckVal = "C5" + setLength(card[2]) + card[2];
            BC_subtagC6_implVersNum = "C6001" + "1";
            tag_BC_substring = BC_subtagC2_pieType +
                BC_subtagC3_KeyId +
                BC_subtagC4_phaseBit +
                BC_subtagC5_intgCheckVal +
                BC_subtagC6_implVersNum;
            tag_BC = 'BC' + setLength(tag_BC_substring) + tag_BC_substring;
            subfid9B = tag_BA + tag_BB + tag_BC;
            var results = {};
            results.subfid9B = subfid9B;
            results.encrypttedCardNumResult = card[0];
            return results;
       
}
function setLength(res) {
	
    if (res.length < 10) {
        return "00" + res.length;
    } else if (res.length >= 10 && res.length < 100) {
        return "0" + res.length;
    } else {
        return res.length;
    }
}


function Savedata(e) {
    var expDate = $("#wag-cko-pm-sel-cc-exp-mon").val();
    var splitMMYY = expDate.split(" / ");
    var saveCreditDetail = {}
    var url = window.location.protocol + "//" + window.location.host  + "/tender/v1/cc";
    var creditcardvalue = getNumber($("#credit_card_value").val());
    if (isValidCredit && isValidExpDate && $("#paymentForm").valid()) {
        var result = volatageCard(getNumber(creditcardvalue));
        if (result === 'Success') {
            showLoading();
            saveCreditDetail = {
                "requestId": "12352368",
                "amount": reqJson.orderTotal.toFixed(2),
                "cartId": reqJson.cartId,
                "sourceSite": reqJson.sourceSite,
                "requesterId": reqJson.requesterId,
                "cardInfo": {
                    "cardType": CCType,
                    "cartPieEncryptedData": encrypetedCardNo,
                    "cardSubfid9B": subfid9B,
                    "expiryMonth": splitMMYY[0],
                    "expiryYear": "20" + splitMMYY[1],
                    "billingContact": {
                        "firstName": $("#addfirstName").val(),
                        "lastName": $("#addlastName").val(),
                        "addressLines": [$("#addstreet1").val()],
                        "city": $("#addcity").val(),
                        "state": $("#addstate").val(),
                        "zipCode": $("#addzipcode").val(),
                        "zipCodeExt": $("#wag-joinbr-zipcodememoptional").val()
                    }
                },
                "type": "CC"
            }
            if (isLoggedIn) {
                saveCreditDetail.saveAsPreferred = $('.checkbox-billingAddr:visible').is(":checked") ? true : false;
            }
        }
        else if(result === 'Invalid'){
            document.getElementById('wag-Payment-globle-error').classList.remove("wag-hide");
            document.getElementById('wag-Payment-globle-error-text').innerHTML = "Invalid Card Type";
            window.scrollTo(500, 0);
        }
        else {
            document.getElementById('wag-Payment-globle-error').classList.remove("wag-hide");
            document.getElementById('wag-Payment-globle-error-text').innerHTML = "Service not available";
            window.scrollTo(500, 0);
        }
    } else {
        $("#paymentForm").valid();
        window.scrollTo(500, 0);
    }

    var request = JSON.stringify(saveCreditDetail);
    if (Object.keys(saveCreditDetail).length !== 0) {
        hitCreditServiceUrl(request, url, serviceRes);
    }
    function serviceRes(ajaxRes) {
        if (ajaxRes) {
            if (ajaxRes.statusCode === 101) {
                window.location.href = window.location.protocol + "//" + window.location.host + ajaxRes.destination;
                console.log("Destination Path " + ajaxRes.destination)
            } else {
                console.log(ajaxRes.messages[0].message);
                document.getElementById('wag-Payment-globle-error').classList.remove("wag-hide");
                document.getElementById('wag-Payment-globle-error-text').innerHTML = ajaxRes.messages[0].message;
            }
        } hideLoading();
    }

    e.preventDefault();
}

function getGenCCTokenKey(encrypetedCardNo,subfid9B){
      ccTokenKey = "";
      var genCCTokenKeyRequest = {}
      var url = window.location.protocol + "//" + window.location.host + "/tender/v1/gencctokenkey";
      genCCTokenKeyRequest = {
                  "requestId": "12352368",
                  "requester": reqJson.sourceSite,
                  "cardInfo": {
                        "cartPieEncryptedData": encrypetedCardNo,
                "cardSubfid9B": subfid9B
                  }
      }
      var req = JSON.stringify(genCCTokenKeyRequest);
    if (Object.keys(genCCTokenKeyRequest).length !== 0) {
        hitCreditServiceUrl(req, url, serviceResponse);
    }
    function serviceResponse(ajaxRes) {
        if (ajaxRes) {
            if (ajaxRes.statusCode === 101) {
                  ccTokenKey = ajaxRes.tokenKey;
            } else {
                document.getElementById('wag-Payment-globle-error').classList.remove("wag-hide");
                document.getElementById('wag-Payment-globle-error-text').innerHTML = "We apologize, we are not able to complete your order at this time. Please check the card information entered or call customer care for assistance in placing your order.";
                hideLoading();
                return;
            }
        }
    }
}

function SavedataWithGenCCToken(e) {
    var expDate = $("#wag-cko-pm-sel-cc-exp-mon").val();
    var splitMMYY = expDate.split(" / ");
    var saveCreditDetail = {}
    var url = window.location.protocol + "//" + window.location.host + "/tendercloud/v1/cctoken";
    if (isValidCredit && isValidExpDate && $("#paymentForm").valid()) {
       
        if (ccTokenKey !== "") {
            showLoading();
            saveCreditDetail = {
                "requestId": "12352368",
                "amount": reqJson.orderTotal.toFixed(2),
                "cartId": reqJson.cartId,
                "sourceSite": reqJson.sourceSite,
                "requesterId": reqJson.requesterId,
                "cardInfo": {
                    "cardType": CCType,
                    "tokenKey": ccTokenKey,
                    "expiryMonth": splitMMYY[0],
                    "expiryYear": "20" + splitMMYY[1],
                    "billingContact": {
                        "firstName": $("#addfirstName").val(),
                        "lastName": $("#addlastName").val(),
                        "addressLines": [$("#addstreet1").val()],
                        "city": $("#addcity").val(),
                        "state": $("#addstate").val(),
                        "zipCode": $("#addzipcode").val(),
                        "zipCodeExt": $("#wag-joinbr-zipcodememoptional").val()
                    }
                },
                "type": "CC"
            }
            if (isLoggedIn) {
                saveCreditDetail.saveAsPreferred = $('.checkbox-billingAddr:visible').is(":checked") ? true : false;
            }
        }
        else {
            $('html, body').scrollTop(0);
        }
    } else {
        $("#paymentForm").valid();
    }

    var request = JSON.stringify(saveCreditDetail);
    if (Object.keys(saveCreditDetail).length !== 0) {
        hitCreditServiceUrl(request, url, serviceRes);
    }
    function serviceRes(ajaxRes) {
        if (ajaxRes) {
            if (ajaxRes.statusCode === 101) {
                window.location.href = window.location.protocol + "//" + window.location.host + ajaxRes.destination;
                console.log("Destination Path " + ajaxRes.destination)
            } else {
                console.log(ajaxRes.messages[0].message);
                document.getElementById('wag-Payment-globle-error').classList.remove("wag-hide");
                document.getElementById('wag-Payment-globle-error-text').innerHTML = ajaxRes.messages[0].message;
                $('html, body').scrollTop(0);
            }
        } hideLoading();
    }

    e.preventDefault();
}

function hitCreditServiceUrl(request, url, callback) {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
      if (this.readyState === 4) {
            if(this.status === 200){
                  var ajaxRes = JSON.parse(this.responseText);
                callback(ajaxRes);
            }
            else {
                  document.getElementById('wag-Payment-globle-error').classList.remove("wag-hide");
                document.getElementById('wag-Payment-globle-error-text').innerHTML = "Unable to Process Payment";
                $('html, body').scrollTop(0);
                        hideLoading();
            }
      }
    };
    xhttp.open("POST", url, true);
    xhttp.timeout = 27000;
    var token = $("meta[name='_csrf']").attr("content");
      var header = $("meta[name='_csrf_header']").attr("content");
      xhttp.setRequestHeader(header, token);
    xhttp.setRequestHeader('Content-Type', 'application/json');
      xhttp.ontimeout = function () {
            hideLoading();
      };
    xhttp.send(request);
}
function seeSavingModal()
{
      $('.wag-checkout-content').on('click', '.clickForOverlay', function () {
            var elementId = $(this).attr('data-targetid');
            if(browserWidth <=767){
                  $('#' + elementId).css({left:"760px"});
                  $('#' + elementId).removeClass('hide-modal');
                  $('#' + elementId).addClass('show-modal');
                  setTimeout(function(){
                        $('#' + elementId).css({left:"0px"});
                  },300);
            }
            else{
                  $('#' + elementId).removeClass('hide-modal');
                  $('#' + elementId).addClass('show-modal');
            }
      })

      $('.wag-checkout-content').on('click', '.action__close-modal', function (e) {
            var modalElement = $(this).closest('.show-modal');
            if(!e.keyCode){
                  if(browserWidth <=767){
                        modalElement.css({left:"760px"});
                        setTimeout(function(){
                              modalElement.addClass('hide-modal');
                              modalElement.removeClass('show-modal');
                        },500);
                        document.getElementById("wag-cac-total-see-details").focus();
                  }
                  else {
                        modalElement.addClass('hide-modal');
                        modalElement.removeClass('show-modal');
                        document.getElementById("wag-cac-total-see-details").focus();
                  }
            }
            else{
                  if(e.keyCode === 13){
                        modalElement.addClass('hide-modal');
                        modalElement.removeClass('show-modal');
                        document.getElementById("wag-cac-total-see-details").focus();
                  }
            }
      });
}

/* istanbul ignore next */
function handleModalFocus(currentElement){
      var firstElement = currentElement + "CloseIcon", lastElement = currentElement + "CloseButton";
      setTimeout(function(){
            $("#"+firstElement).trigger("focus");
      }, 400);
      
      var start = document.getElementById(firstElement);
      var end = document.getElementById(lastElement);
      start.addEventListener('keydown', function(e){
            if(e.keyCode===9 && e.shiftKey){
                  end.focus();
                  e.preventDefault();
            }
      });
      end.addEventListener('keydown', function(e){
            if(e.keyCode === 9 && !(e.shiftKey && e.keyCode === 9)){
                  start.focus();
                  e.preventDefault();
            }
      });
}

function CloseModals()
{
       $('body').css('overflow', 'scroll')
       if($("#paypal-Seeterms").hasClass("show-modal")){
             $("#paypal-Seeterms").removeClass("show-modal");
             document.getElementById("paypalSeeTermsLink").focus();
       }
       else if($("#savingsAndOffersModal").hasClass("show-modal")){
             $("#savingsAndOffersModal").removeClass("show-modal");
             document.getElementById("wag-cac-total-see-details").focus();
       }
}

/**
 * Check daylight saving time prototype
 */
Date.prototype.stdTimezoneOffset = function() {
    var jan = new Date(this.getFullYear(), 0, 1);
    var jul = new Date(this.getFullYear(), 6, 1);
    return Math.max(jan.getTimezoneOffset(), jul.getTimezoneOffset());
}

/**
 * Check daylight is daylight time
 */
Date.prototype.dst = function() {
    return this.getTimezoneOffset() < this.stdTimezoneOffset();
}

function chatNow(){
      if( sessionStorage.getItem("gncac") === "true" ){
            $("#salesforceChat").addClass('hide');

            var today = new Date();
            var isDST = today.dst() ? true : false;
            var cstOffset = isDST ? 5 : 6;
            cstOffset = cstOffset * 60 * 60 * 1000;
            var todayMillis = today.getTime();
            var curretCST = todayMillis - cstOffset;
            var cstHours = new Date(curretCST).getUTCHours();
            
            var chatStartTime = parseInt(commonUiConfig.chatStartTime);
            var chatEndTime = parseInt(commonUiConfig.chatEndTime);
            if (cstHours >= chatStartTime  && cstHours < chatEndTime) {
               $("#help-chatnow").removeClass('hide');
            }
      }
      else{
            $("#genesysChat").addClass('hide');
      }
}

function loadGensysScript(){
      if( sessionStorage.getItem("gncac") === "true" ){
            $(document).find('head').append('<link rel="stylesheet" type="text/css" href="' + commonUiConfig.gensysChatCssUrl + '" />');

            var script = document.createElement("script");
          script.src = commonUiConfig.gensysChatJsUrl;
          script.type = "text/javascript";
          document.getElementById("wag-chat-script-container").appendChild(script);
      }
}

module.exports = getEncryptionValue;


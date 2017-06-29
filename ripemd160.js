/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
/** @preserve
(c) 2012 by Cédric Mesnil. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

var helpers = require('./helpers');

/**
 * CryptoJS core components.
 */
var CryptoJS = function () {
    /**
     * CryptoJS namespace.
     */
    var C = {};

    /**
     * Library namespace.
     */
    var C_lib = C.lib = {};

    /**
     * Base object for prototypal inheritance.
     */
    var C_lib_Base = C_lib.Base = (function () {
        function F() {}

        return {
            /**
             * Creates a new object that inherits from this object.
             *
             * @param {Object} overrides Properties to copy into the new object.
             *
             * @return {Object} The new object.
             *
             * @static
             */
            extend: function (overrides) {
                // Spawn
                F.prototype = this;
                var subtype = new F();

                // Augment
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                // Reference supertype
                subtype.$super = this;

                return subtype;
            },

            /**
             * Copies properties into this object.
             *
             * @param {Object} properties The properties to mix in.
             */
            mixIn: function (properties) {
                for (var p in properties) {
                    if (properties.hasOwnProperty(p)) {
                        this[p] = properties[p];
                    }
                }

                // IE won't copy toString using the loop above
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            /**
             * Extends this object and runs the init method.
             * Arguments to create() will be passed to init().
             *
             * @return {Object} The new object.
             *
             * @static
             */
            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);

                return instance;
            },

            /**
             * Initializes a newly created object.
             * Override this method to add some logic when your objects are created.
             */
            init: function () {
            },

            /**
             * Tests if this object is a descendant of the passed type.
             *
             * @param {CryptoJS.lib.Base} type The potential ancestor.
             *
             * @return {boolean}
             */
            isA: function (type) {
                var o = this;

                while (o) {
                    if (o == type) {
                        return true;
                    } else {
                        o = o.$super;
                    }
                }

                return false;
            },

            /**
             * Creates a copy of this object.
             *
             * @return {Object} The clone.
             */
            clone: function () {
                return this.$super.extend(this);
            }
        };
    }());

    /**
     * An array of 32-bit words.
     *
     * @property {Array} words The array of 32-bit words.
     * @property {number} sigBytes The number of significant bytes in this word array.
     * @property {CryptoJS.enc.*} encoder
     *   The default encoding strategy to convert this word array to a string. Default: CryptoJS.enc.Hex
     */
    // Technical note: The default encoder can be set only after the encoders have been defined,
    // therefore that assignment appears farther down in this file.
    var C_lib_WordArray = C_lib.WordArray = C_lib_Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes !== undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        /**
         * Converts this word array to a string.
         *
         * @param {CryptoJS.enc.*} encoder (Optional) The encoding strategy to use.
         *
         * @return {string} The stringified word array.
         */
        toString: function (encoder) {
            return (encoder || this.encoder).toString(this);
        },

        /**
         * Concatenates a word array to this word array.
         *
         * @param {CryptoJS.lib.WordArray} wordArray The word array to append.
         *
         * @return {CryptoJS.lib.WordArray} This word array.
         */
        concat: function (wordArray) {
            // Shortcuts
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;

            // Clear excess bits
            this.clamp();

            // Concat
            for (var i = 0; i < thatSigBytes; i++) {
                var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                thisWords[thisSigBytes >>> 2] |= thatByte << (24 - (thisSigBytes % 4) * 8);
                thisSigBytes++;
            }
            this.sigBytes = thisSigBytes;

            // Chainable
            return this;
        },

        /**
         * Removes insignificant bits.
         */
        clamp: function () {
            // Shortcuts
            var words = this.words;
            var sigBytes = this.sigBytes;

            // Clamp
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {CryptoJS.lib.WordArray} The clone.
         */
        clone: function () {
            var clone = C_lib_WordArray.$super.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {CryptoJS.lib.WordArray} The random word array.
         *
         * @static
         */
        random: function (nBytes) {
            var words = [];
            for (var i = 0; i < nBytes; i += 4) {
                words.push(Math.floor(Math.random() * 0x100000000));
            }

            return this.create(words, nBytes);
        }
    });

    /**
     * Base hash template.
     *
     * @property {number} _blockSize The number of 32-bit words this hash operates on. Default: 16 (512 bits)
     */
    var C_lib_Hash = C_lib.Hash = C_lib_Base.extend({
        _cfg: C_lib_Base.extend(),

        /**
         * Initializes a newly created hasher.
         */
        init: function (cfg) {
            this._cfg = this._cfg.extend(cfg);

            this.reset();
        },

        /**
         * Resets this hash to its initial state.
         */
        reset: function () {
            // Initial values
            var hash = this._hash = C_lib_WordArray.create();
            this._message = C_lib_WordArray.create();
            this._length = 0;

            // Perform hash-specific logic
            this._doReset();

            // Update sigBytes using length of hash
            hash.sigBytes = hash.words.length * 4;
        },

        /**
         * Updates this hash with a message.
         *
         * @param {CryptoJS.lib.WordArray|string} messageUpdate The message to append.
         *
         * @return {CryptoJS.lib.Hash} This hash instance.
         */
        update: function (messageUpdate) {
            // Convert string to WordArray, else assume WordArray already
            if (typeof messageUpdate == 'string') {
                messageUpdate = C_enc_Utf8.fromString(messageUpdate);
            }

            // Append
            this._message.concat(messageUpdate);
            this._length += messageUpdate.sigBytes;

            // Update the hash
            this._hashBlocks(false);

            // Chainable
            return this;
        },


       /** Updates this hash.
       *                           */
       _hashBlocks: function (nulltLast) {
           // Shortcuts
           var message = this._message;
           var sigBytes = message.sigBytes;
           var blockSize = this._blockSize;
           var nBlocksReady = Math.floor(sigBytes / (blockSize * 4));
           
           if (nBlocksReady) {
               var nWordsReady = nBlocksReady * blockSize;
               for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    // Need to incorporate t value into V of last 
                    // block processed.
                    var nullt = false
                    if (message.words.length == blockSize && nulltLast) {
                        nullt = true;
                    }
                    this._doHashBlock(0, nullt);
                    message.words.splice(0, blockSize);
                    message.sigBytes = sigBytes - nWordsReady * 4;
               }
           }
       },

        /**
         * Completes this hash computation, then resets this hash to its initial state.
         *
         * @param {CryptoJS.lib.WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {CryptoJS.lib.WordArray} The hash.
         */
        compute: function (messageUpdate) {
            // Final message update
            if (messageUpdate) {
                this.update(messageUpdate);
            }

            // Perform hash-specific logic
            this._doCompute();

            // Retain hash after reset
            var hash = this._hash;

            this.reset();

            return hash;
        },

        _blockSize: 512/32,

        /**
         * Creates a shortcut function to a hash algorithm's object interface.
         *
         * @param {CryptoJS.lib.Hash} hasher The hash algorithm to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         */
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return hasher.create(cfg).compute(message);
            };
        },

        /**
         * Creates a shortcut function to the HMAC algorithm's object interface.
         *
         * @param {CryptoJS.lib.Hash} hasher The hash algorithm to use with this helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         */
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return C_algo.HMAC.create(hasher, key).compute(message);
            };
        }
    });

    /**
     * Encoding namespace.
     */
    var C_enc = C.enc = {};

    /**
     * Hex encoding strategy.
     */
    var C_enc_Hex = C_enc.Hex = {
        /**
         * Converts a word array to a hex string.
         *
         * @param {CryptoJS.lib.WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         */
        toString: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var hexStr = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexStr.push((bite >>> 4).toString(16));
                hexStr.push((bite & 0x0f).toString(16));
            }

            return hexStr.join('');
        },

        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {CryptoJS.lib.WordArray} The word array.
         *
         * @static
         */
        fromString: function (hexStr) {
            // Shortcut
            var hexStrLength = hexStr.length;

            // Convert
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return C_lib_WordArray.create(words, hexStrLength / 2);
        }
    };

    /**
     * Latin1 encoding strategy.
     */
    var C_enc_Latin1 = C_enc.Latin1 = {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {CryptoJS.lib.WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         */
        toString: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var latin1Str = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Str.push(String.fromCharCode(bite));
            }

            return latin1Str.join('');
        },

        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {CryptoJS.lib.WordArray} The word array.
         *
         * @static
         */
        fromString: function (latin1Str) {
            // Shortcut
            var latin1StrLength = latin1Str.length;

            // Convert
            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= latin1Str.charCodeAt(i) << (24 - (i % 4) * 8);
            }

            return C_lib_WordArray.create(words, latin1StrLength);
        }
    };

    /**
     * UTF-8 encoding strategy.
     */
    var C_enc_Utf8 = C_enc.Utf8 = {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {CryptoJS.lib.WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         */
        toString: function (wordArray) {
            return decodeURIComponent(escape(C_enc_Latin1.toString(wordArray)));
        },

        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {CryptoJS.lib.WordArray} The word array.
         *
         * @static
         */
        fromString: function (utf8Str) {
            return C_enc_Latin1.fromString(unescape(encodeURIComponent(utf8Str)));
        }
    };

    // Set WordArray default encoder
    C_lib_WordArray.encoder = C_enc_Hex;

    /**
     * Algorithm namespace.
     */
    var C_algo = C.algo = {};

    return C;
}();
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var Hasher = C_lib.Hash;
    var C_algo = C.algo;

    // Constants table
    var _zl = WordArray.create([
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
        7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
        3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
        1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
        4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13]);
    var _zr = WordArray.create([
        5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
        6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
        8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11]);
    var _sl = WordArray.create([
         11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
        7, 6,   8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
          11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
        9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ]);
    var _sr = WordArray.create([
        8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
        9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
        9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
        8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ]);

    var _hl =  WordArray.create([ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
    var _hr =  WordArray.create([ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);

    /**
     * RIPEMD160 hash algorithm.
     */
    var RIPEMD160 = C_algo.RIPEMD160 = Hasher.extend({
        _doReset: function () {
            this._hash  = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
        },

        _doProcessBlock: function (M, offset) {

            // Swap endian
            for (var i = 0; i < 16; i++) {
                // Shortcuts
                var offset_i = offset + i;
                var M_offset_i = M[offset_i];

                // Swap
                M[offset_i] = (
                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
                );
            }
            // Shortcut
            var H  = this._hash.words;
            var hl = _hl.words;
            var hr = _hr.words;
            var zl = _zl.words;
            var zr = _zr.words;
            var sl = _sl.words;
            var sr = _sr.words;

            // Working variables
            var al, bl, cl, dl, el;
            var ar, br, cr, dr, er;

            ar = al = H[0];
            br = bl = H[1];
            cr = cl = H[2];
            dr = dl = H[3];
            er = el = H[4];
            // Computation
            var t;
            for (var i = 0; i < 80; i += 1) {
                t = (al +  M[offset+zl[i]])|0;
                if (i<16){
	            t +=  f1(bl,cl,dl) + hl[0];
                } else if (i<32) {
	            t +=  f2(bl,cl,dl) + hl[1];
                } else if (i<48) {
	            t +=  f3(bl,cl,dl) + hl[2];
                } else if (i<64) {
	            t +=  f4(bl,cl,dl) + hl[3];
                } else {// if (i<80) {
	            t +=  f5(bl,cl,dl) + hl[4];
                }
                t = t|0;
                t =  rotl(t,sl[i]);
                t = (t+el)|0;
                al = el;
                el = dl;
                dl = rotl(cl, 10);
                cl = bl;
                bl = t;

                t = (ar + M[offset+zr[i]])|0;
                if (i<16){
	            t +=  f5(br,cr,dr) + hr[0];
                } else if (i<32) {
	            t +=  f4(br,cr,dr) + hr[1];
                } else if (i<48) {
	            t +=  f3(br,cr,dr) + hr[2];
                } else if (i<64) {
	            t +=  f2(br,cr,dr) + hr[3];
                } else {// if (i<80) {
	            t +=  f1(br,cr,dr) + hr[4];
                }
                t = t|0;
                t =  rotl(t,sr[i]) ;
                t = (t+er)|0;
                ar = er;
                er = dr;
                dr = rotl(cr, 10);
                cr = br;
                br = t;
            }
            // Intermediate hash value
            t    = (H[1] + cl + dr)|0;
            H[1] = (H[2] + dl + er)|0;
            H[2] = (H[3] + el + ar)|0;
            H[3] = (H[4] + al + br)|0;
            H[4] = (H[0] + bl + cr)|0;
            H[0] =  t;
        },

        _doFinalize: function () {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;

            var nBitsTotal = this._nDataBytes * 8;
            var nBitsLeft = data.sigBytes * 8;

            // Add padding
            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
                (((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
                (((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
            );
            data.sigBytes = (dataWords.length + 1) * 4;

            // Hash final blocks
            this._process();

            // Shortcuts
            var hash = this._hash;
            var H = hash.words;

            // Swap endian
            for (var i = 0; i < 5; i++) {
                // Shortcut
                var H_i = H[i];

                // Swap
                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
            }

            // Return final computed hash
            return hash;
        },

        clone: function () {
            var clone = Hasher.clone.call(this);
            clone._hash = this._hash.clone();

            return clone;
        }
    });


    function f1(x, y, z) {
        return ((x) ^ (y) ^ (z));

    }

    function f2(x, y, z) {
        return (((x)&(y)) | ((~x)&(z)));
    }

    function f3(x, y, z) {
        return (((x) | (~(y))) ^ (z));
    }

    function f4(x, y, z) {
        return (((x) & (z)) | ((y)&(~(z))));
    }

    function f5(x, y, z) {
        return ((x) ^ ((y) |(~(z))));

    }

    function rotl(x,n) {
        return (x<<n) | (x>>>(32-n));
    }


    /**
     * Shortcut function to the hasher's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     *
     * @return {WordArray} The hash.
     *
     * @static
     *
     * @example
     *
     *     var hash = CryptoJS.RIPEMD160('message');
     *     var hash = CryptoJS.RIPEMD160(wordArray);
     */
    C.RIPEMD160 = Hasher._createHelper(RIPEMD160);

    /**
     * Shortcut function to the HMAC's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     * @param {WordArray|string} key The secret key.
     *
     * @return {WordArray} The HMAC.
     *
     * @static
     *
     * @example
     *
     *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
     */
    C.HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160);

// Wrap existing blake function in this.
function core_ripemd160(x, len) {
    var out = C.RIPEMD160(CryptoJS.enc.Hex.fromString(x.toString('hex')));
    var HASH = out.words;
    return HASH;
}

module.exports = function ripemd160(buf) {
    return helpers.hash(buf, core_ripemd160, 20, true);
};

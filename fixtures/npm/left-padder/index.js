'use strict';
/**
 * Pad `str` on the left to `len` characters using `ch` (default space).
 * @param {string} str
 * @param {number} len
 * @param {string} [ch]
 */
function leftPad(str, len, ch) {
  str = String(str);
  ch = ch === undefined || ch === '' ? ' ' : String(ch)[0];
  while (str.length < len) str = ch + str;
  return str;
}

/** Pad a number with zeros, e.g. zeroPad(7, 3) === '007'. */
function zeroPad(n, len) {
  return leftPad(n, len, '0');
}

module.exports = { leftPad, zeroPad };

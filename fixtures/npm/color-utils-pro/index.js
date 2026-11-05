'use strict';
// Legit-looking public API. The interesting part is scripts/setup.js.
function hexToRgb(hex) {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return m ? { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) } : null;
}
function rgbToHex({ r, g, b }) {
  return '#' + [r, g, b].map((x) => x.toString(16).padStart(2, '0')).join('');
}
module.exports = { hexToRgb, rgbToHex };

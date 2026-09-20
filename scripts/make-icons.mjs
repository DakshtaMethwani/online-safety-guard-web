/**
 * Generates the Outlook add-in icons under outlook/ at the sizes the manifest
 * references (16, 32, 64, 80, 128). Run: node scripts/make-icons.mjs
 * Pure Node (zlib) - no image libraries.
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function png(size, pixel) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  let o = 0;
  for (let y = 0; y < size; y++) {
    raw[o++] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixel(x, y);
      raw[o++] = r;
      raw[o++] = g;
      raw[o++] = b;
      raw[o++] = a;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const len2 = dx * dx + dy * dy || 1;
  let t = ((px - ax) * dx + (py - ay) * dy) / len2;
  t = Math.max(0, Math.min(1, t));
  const cx = ax + t * dx;
  const cy = ay + t * dy;
  return Math.hypot(px - cx, py - cy);
}

function makeIcon(size) {
  const bg = [13, 148, 136]; // teal
  const fg = [255, 255, 255];
  const radius = size * 0.22;
  const thickness = Math.max(1, size * 0.11);
  // Check mark control points (fractions of the icon size).
  const p1 = [0.27 * size, 0.53 * size];
  const p2 = [0.43 * size, 0.69 * size];
  const p3 = [0.75 * size, 0.32 * size];

  return png(size, (x, y) => {
    // rounded-square mask
    const cx = Math.min(Math.max(x, radius), size - radius);
    const cy = Math.min(Math.max(y, radius), size - radius);
    const outside = Math.hypot(x - cx, y - cy) > radius;
    if (outside) return [0, 0, 0, 0];

    const d = Math.min(
      distToSegment(x + 0.5, y + 0.5, p1[0], p1[1], p2[0], p2[1]),
      distToSegment(x + 0.5, y + 0.5, p2[0], p2[1], p3[0], p3[1])
    );
    if (d <= thickness / 2) return [...fg, 255];
    return [...bg, 255];
  });
}

const outDir = path.join(process.cwd(), "outlook");
fs.mkdirSync(outDir, { recursive: true });
for (const size of [16, 32, 64, 80, 128]) {
  const file = path.join(outDir, `icon-${size}.png`);
  fs.writeFileSync(file, makeIcon(size));
  console.log(`wrote ${file} (${fs.statSync(file).size} bytes)`);
}

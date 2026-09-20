/**
 * Copies the served Outlook add-in assets from outlook/ into dist/outlook/ at
 * build time (excluding the manifest, which must never be served). Keeps the
 * Docker image working, since only dist/ is copied into the run stage.
 */
import fs from "node:fs";
import path from "node:path";

const src = path.join(process.cwd(), "outlook");
const dest = path.join(process.cwd(), "dist", "outlook");

if (!fs.existsSync(src)) {
  console.error("copy-outlook: outlook/ directory not found");
  process.exit(1);
}

fs.rmSync(dest, { recursive: true, force: true });
fs.cpSync(src, dest, {
  recursive: true,
  filter: (source) => path.basename(source).toLowerCase() !== "manifest.xml",
});
console.log("copy-outlook: outlook/ -> dist/outlook/ (manifest excluded)");

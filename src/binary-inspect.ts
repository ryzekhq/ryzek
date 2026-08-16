import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";

/**
 * Binary / archive payload inspection.
 *
 * The documented bypass this closes: published research defeated every
 * public skill scanner tested, partly by hiding logic in binary and archive
 * formats. A text-pattern scanner reads a `.zip` or a compiled `.so` as
 * meaningless bytes, matches nothing, and reports the skill clean — which is
 * a worse outcome than reporting nothing at all, because it manufactures
 * false confidence.
 *
 * The honest design, and the reasoning behind it:
 *
 *   1. A static scanner CANNOT determine what a compiled binary does. Any
 *      tool claiming otherwise for arbitrary executables is overselling.
 *      So the finding here is not "this binary is malicious" — it is
 *      "this skill ships something a reviewer cannot read." For an agent
 *      skill, that is itself the problem: skills are supposed to be
 *      auditable text, and an opaque blob defeats the entire review model.
 *
 *   2. Where the container is transparent (gzip, tar.gz — both handled by
 *      Node's built-in zlib), it decompresses and returns the inner content
 *      so the normal rules can scan it. Compression is not obfuscation, and
 *      treating it as unreadable would be lazy.
 *
 *   3. Zip requires a third-party dependency, which this project
 *      deliberately avoids — every dependency is code that runs inside a
 *      user's CI. Zips are therefore flagged as opaque rather than
 *      extracted. That is a stated limitation, not a silent gap.
 */

/** Extensions that are executable or otherwise unreadable to a human reviewer. */
const BINARY_EXTENSIONS = new Set([
  ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
  ".pyc", ".pyo", ".class", ".jar", ".wasm",
  ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".apk",
]);

/** Archive containers. Some we can open, some we cannot — see ARCHIVE_EXTRACTABLE. */
const ARCHIVE_EXTENSIONS = new Set([
  ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
]);

const ARCHIVE_EXTRACTABLE = new Set([".gz", ".tgz"]);

/**
 * Magic-byte signatures. Checked in addition to extensions because renaming
 * `payload.exe` to `notes.txt` is the first thing anyone hiding something
 * would try — the extension is a hint, the header is evidence.
 */
const MAGIC_SIGNATURES: { name: string; bytes: number[]; extractable?: boolean }[] = [
  { name: "ZIP archive", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { name: "gzip archive", bytes: [0x1f, 0x8b], extractable: true },
  { name: "Windows PE executable", bytes: [0x4d, 0x5a] },
  { name: "ELF executable", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: "Mach-O executable", bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { name: "Java class file", bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { name: "WebAssembly module", bytes: [0x00, 0x61, 0x73, 0x6d] },
  { name: "7-Zip archive", bytes: [0x37, 0x7a, 0xbc, 0xaf] },
  { name: "RAR archive", bytes: [0x52, 0x61, 0x72, 0x21] },
  { name: "Python bytecode", bytes: [0x6f, 0x0d, 0x0d, 0x0a] },
];

export interface OpaqueFile {
  relPath: string;
  /** What it appears to be, by magic bytes if available, else by extension. */
  kind: string;
  sizeBytes: number;
  /** True when the extension claims one thing and the header says another. */
  extensionMismatch: boolean;
  /** Content recovered by decompression, if we could open it. */
  extractedText?: string;
}

function matchMagic(buf: Buffer): { name: string; extractable?: boolean } | null {
  for (const sig of MAGIC_SIGNATURES) {
    if (buf.length < sig.bytes.length) continue;
    if (sig.bytes.every((b, i) => buf[i] === b)) return sig;
  }
  return null;
}

/**
 * Heuristic for a file that is text-shaped but not human-readable — a large
 * unbroken base64 blob, which is the usual way binary content gets smuggled
 * into a file that "looks like" text.
 */
export function findEncodedBlob(text: string): { snippet: string; length: number } | null {
  const match = text.match(/[A-Za-z0-9+/]{400,}={0,2}/);
  if (!match) return null;
  return { snippet: match[0].slice(0, 48) + "…", length: match[0].length };
}

function tryDecompress(full: string, kind: string): string | undefined {
  if (!kind.includes("gzip")) return undefined;
  try {
    const raw = fs.readFileSync(full);
    const out = zlib.gunzipSync(raw);
    // Only return it if it actually looks like text — a gzipped binary is
    // still opaque and shouldn't be presented as reviewable content.
    const text = out.toString("utf-8");
    const printableRatio =
      (text.match(/[\x20-\x7E\s]/g) || []).length / Math.max(text.length, 1);
    return printableRatio > 0.85 ? text.slice(0, 20000) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Walks a skill directory looking for anything a reviewer could not read.
 * Read-only: it never executes, and it only decompresses formats handled by
 * Node's own zlib.
 */
export function findOpaqueFiles(skillDir: string, maxFiles = 40): OpaqueFile[] {
  const found: OpaqueFile[] = [];

  const walk = (dir: string, depth: number): void => {
    if (depth > 4 || found.length >= maxFiles) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (found.length >= maxFiles) return;
      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name.startsWith(".git")) continue;
        walk(full, depth + 1);
        continue;
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(full);
      } catch {
        continue;
      }
      if (stat.size === 0) continue;

      const ext = path.extname(entry.name).toLowerCase();
      const extLooksBinary = BINARY_EXTENSIONS.has(ext) || ARCHIVE_EXTENSIONS.has(ext);

      // Read a small header for magic-byte checking.
      let header: Buffer;
      try {
        const fd = fs.openSync(full, "r");
        header = Buffer.alloc(16);
        fs.readSync(fd, header, 0, 16, 0);
        fs.closeSync(fd);
      } catch {
        continue;
      }

      const magic = matchMagic(header);

      if (!magic && !extLooksBinary) continue;

      const kind = magic ? magic.name : `${ext} file`;
      // A mismatch means the name is hiding what the file actually is.
      const extensionMismatch = Boolean(magic) && !extLooksBinary;

      const extractedText =
        magic?.extractable || ARCHIVE_EXTRACTABLE.has(ext)
          ? tryDecompress(full, kind)
          : undefined;

      found.push({
        relPath: path.relative(skillDir, full),
        kind,
        sizeBytes: stat.size,
        extensionMismatch,
        extractedText,
      });
    }
  };

  walk(skillDir, 0);
  return found;
}

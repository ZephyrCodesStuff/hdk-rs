import init, { Sdat, Bar, Sharc, WasmMapper as Mapper } from '../pkg/hdk_wasm.js';
import { zipSync } from 'https://cdn.skypack.dev/fflate?min';

const ARCHIVE_MAGIC = 0xADEF17E1;

const SHARC_DEFAULT_KEY = new Uint8Array([
    0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25, 0xFA, 0x81,
    0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21, 0x40, 0x47, 0x02, 0xDC,
]);

const SHARC_SDAT_KEY = new Uint8Array([
    0xF1, 0xBF, 0x6A, 0x4F, 0xBB, 0xBA, 0x5D, 0x0E, 0xD2, 0x7F, 0x41, 0x8A, 0x48, 0x88, 0xAF, 0x30,
    0x47, 0x86, 0xEC, 0xD4, 0x4E, 0x2D, 0x36, 0x46, 0x80, 0xDB, 0x4D, 0xF2, 0x22, 0x3A, 0x9F, 0x56,
]);

const BAR_DEFAULT_KEY = new Uint8Array([
    0x80, 0x6D, 0x79, 0x16, 0x23, 0x42, 0xA1, 0x0E, 0x8F, 0x78, 0x14, 0xD4, 0xF9, 0x94, 0xA2, 0xD1,
    0x74, 0x13, 0xFC, 0xA8, 0xF6, 0xE0, 0xB8, 0xA4, 0xED, 0xB9, 0xDC, 0x32, 0x7F, 0x8B, 0xA7, 0x11,
]);

const BAR_SIGNATURE_KEY = new Uint8Array([
    0xEF, 0x8C, 0x7D, 0xE8, 0xE5, 0xD5, 0xD6, 0x1D, 0x6A, 0xAA, 0x5A, 0xCA, 0xF7, 0xC1, 0x6F, 0xC4,
    0x5A, 0xFC, 0x59, 0xE4, 0x8F, 0xE6, 0xC5, 0x93, 0x7E, 0xBD, 0xFF, 0xC1, 0xE3, 0x99, 0x9E, 0x62,
]);

function hexToBytes(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2 !== 0) throw new Error('Hex length must be even');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
}

function log(msg) {
    const el = document.getElementById('log');
    if (el) {
        el.textContent += `${msg}\n`;
        el.scrollTop = el.scrollHeight;
    }
}

function read_u32_le(bytes, off = 0) {
    return (bytes[off]) | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24);
}

function read_u32_be(bytes, off = 0) {
    return (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | (bytes[off + 3]);
}

function createDownloadLink(data, filename, text) {
    const blob = new Blob([data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.textContent = text;
    document.body.appendChild(a);
    document.body.appendChild(document.createElement('br'));
}

function tryExtractArchive(payload, keysHex, uuid = null, baseName = "unpacked") {
    try {
        const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
        if (bytes.length < 8) return null;

        const le = read_u32_le(bytes, 0);
        const be = read_u32_be(bytes, 0);
        let endian = null;
        if ((le >>> 0) === ARCHIVE_MAGIC) endian = 'little';
        else if ((be >>> 0) === ARCHIVE_MAGIC) endian = 'big';
        else return null;

        const ver_flags = endian === 'little' ? read_u32_le(bytes, 4) : read_u32_be(bytes, 4);
        const version = (ver_flags >>> 16) & 0xFFFF;

        log(`Detected archive magic. Endian=${endian} version=${version}`);

        // Initialize mapper for name recovery
        const mapper = new Mapper(uuid || null, true);

        // Use the base filename to recover potential archive name associations
        const filenameScan = new TextEncoder().encode(`file://${baseName}.scene\n${baseName}.bar\n${baseName}.sharc\n`);
        mapper.scan(filenameScan);

        const tempEntries = {};

        // Try SHARC (version 512)
        if (version === 512) {
            log('Attempting SHARC extraction...');
            let key = SHARC_SDAT_KEY;
            try {
                const clean = keysHex.replace(/[^0-9a-fA-F]/g, '');
                if (clean.length === 64) {
                    key = hexToBytes(clean);
                }
            } catch (e) { }

            try {
                let sh = null;
                try {
                    sh = new Sharc(bytes, key);
                } catch (e) {
                    log(`SHARC open failed with provided/SDAT key: ${e}. Trying default key...`);
                    sh = new Sharc(bytes, SHARC_DEFAULT_KEY);
                }

                const toc = sh.list_toc();
                log(`SHARC opened successfully with ${toc.length} entries. Scanning for paths...`);

                for (let i = 0; i < toc.length; i++) {
                    const data = sh.read_entry(i);
                    const meta = toc[i];
                    const hash = meta.name_hash || `entry_${i}`;

                    // Scan data for potential file paths to help mapper
                    mapper.scan(data);
                    tempEntries[hash] = data;
                }
            } catch (e) {
                log(`SHARC extraction failed: ${e}`);
                return null;
            }
        }

        // Try BAR (version 256)
        else if (version === 256) {
            log('Attempting BAR extraction...');
            let def = BAR_DEFAULT_KEY, sig = BAR_SIGNATURE_KEY;
            try {
                const clean = keysHex.replace(/[^0-9a-fA-F]/g, '');
                if (clean.length === 128) {
                    const all = hexToBytes(clean);
                    def = all.slice(0, 32);
                    sig = all.slice(32, 64);
                }
            } catch (e) { }

            try {
                const big_endian = (endian === 'big');
                const bar = new Bar(bytes, def, sig, big_endian);
                const toc = bar.list_toc();
                log(`BAR opened successfully with ${toc.length} entries. Scanning for paths...`);

                for (let i = 0; i < toc.length; i++) {
                    const data = bar.read_entry(i);
                    const meta = toc[i];
                    const hash = meta.name_hash || `entry_${i}`;

                    // Scan data for potential file paths to help mapper
                    mapper.scan(data);
                    tempEntries[hash] = data;
                }
            } catch (e) {
                log(`BAR extraction failed: ${e}`);
                return null;
            }
        } else {
            return null;
        }

        // Use accumulated mappings to rename files
        const mappings = mapper.get_mappings();
        const finalEntries = {};
        let mappedCount = 0;

        for (const [hashUpper, data] of Object.entries(tempEntries)) {
            const hashLower = hashUpper.toLowerCase();
            const name = mappings[hashLower] || hashUpper;
            if (mappings[hashLower]) mappedCount++;
            finalEntries[name] = data;
        }

        log(`Mapping complete. Recovered ${mappedCount} / ${Object.keys(tempEntries).length} filenames.`);
        return finalEntries;

    } catch (e) {
        log(`Archive detection error: ${e}`);
        return null;
    }
}

async function main() {
    try {
        await init();
        log('WASM Initialized.');
    } catch (e) {
        log(`WASM Init Failed: ${e}`);
        return;
    }

    const fileInput = document.getElementById('file');
    const keysInput = document.getElementById('keys');
    const btn = document.getElementById('unpack');

    btn.addEventListener('click', async () => {
        try {
            const f = fileInput.files[0];
            if (!f) return log('Please select an SDAT file.');

            const hex = keysInput.value.trim();
            const keys = hexToBytes(hex);
            if (keys.length !== 112) return log('SDAT Keys must be 112 bytes (224 hex chars).');

            log(`Loading ${f.name}...`);
            const ab = await f.arrayBuffer();
            const u8 = new Uint8Array(ab);

            log('Decrypting SDAT...');
            const s = new Sdat(u8, keys);

            let payload;
            try {
                payload = s.decrypt_to_vec();
                log('SDAT decrypted successfully.');
            } catch (e) {
                log(`SDAT decryption failed: ${e}`);
                return;
            }

            const baseName = f.name.replace(/\.sdat$|\.bin$/i, '');

            log('Checking for embedded archive...');
            const uuidInput = document.getElementById('uuid');
            const uuid = uuidInput ? uuidInput.value.trim() : null;
            const entries = tryExtractArchive(payload, hex, uuid, baseName);

            if (entries) {
                const count = Object.keys(entries).length;
                log(`Zipping ${count} entries (no compression)...`);

                // Prepare entries for fflate. zipSync takes level 0 for store.
                const zipMap = {};
                for (const [name, data] of Object.entries(entries)) {
                    zipMap[name] = [data, { level: 0 }];
                }

                try {
                    const zipped = zipSync(zipMap);
                    createDownloadLink(zipped, `${baseName}.zip`, `Download Unpacked ${baseName}.zip (${count} files)`);
                    log('Archive extraction and zipping complete.');
                } catch (e) {
                    log(`Zipping failed: ${e}`);
                }
            } else {
                log('No known archive detected or extraction failed. Providing raw payload.');
                createDownloadLink(payload, `${baseName}.payload`, `Download ${baseName}.payload`);
            }

            log('Done.');

        } catch (e) {
            log(`Error: ${e}`);
            console.error(e);
        }
    });
}

main();


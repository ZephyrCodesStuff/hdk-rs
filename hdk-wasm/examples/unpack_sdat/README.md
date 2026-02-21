# HDK WASM — SDAT Unpack Example

This example demonstrates loading the `hdk-wasm` package in the browser and unpacking an SDAT file to a downloadable payload.

Build and run

1. Build the wasm package from the `hdk-wasm` crate directory:

```bash
cd hdk-wasm
wasm-pack build --target web
```

This produces a `pkg/` directory used by the example.

2. Serve the example folder (from repository root or `hdk-wasm/examples/unpack_sdat`):

```bash
cd hdk-wasm/examples/unpack_sdat
python3 -m http.server 8080
# or: npx serve .
```

3. Open `http://localhost:8080` in a browser, select an SDAT file, paste the 112-byte keys as hex (224 hex chars), and click "Unpack". A download link for the decrypted payload will be added.

Notes

- The example expects the wasm package output at `hdk-wasm/pkg` (relative import `../pkg/hdk_wasm.js`). Adjust the `import` path in `unpack.js` if your build produces a different path.
- For large files prefer chunked streaming; this example uses a full decrypt-to-chunks convenience method.

use std::io::{Cursor, Read, Write};
use wasm_bindgen::prelude::*;

use hdk_comp::lzma::reader::SegmentedLzmaReader;
use hdk_comp::lzma::writer::SegmentedLzmaWriter;
use hdk_comp::zlib::reader::SegmentedZlibReader;
use hdk_comp::zlib::writer::SegmentedZlibWriter;

#[wasm_bindgen]
pub fn lzma_segmented_compress(input: &[u8]) -> Result<Vec<u8>, JsValue> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = SegmentedLzmaWriter::new(cursor);

    writer
        .write_all(input)
        .map_err(|e| JsValue::from_str(&format!("write failed: {}", e)))?;

    let out_cursor = writer
        .finish()
        .map_err(|e| JsValue::from_str(&format!("finish failed: {}", e)))?;

    Ok(out_cursor.into_inner())
}

#[wasm_bindgen]
pub fn lzma_segmented_decompress(input: &[u8]) -> Result<Vec<u8>, JsValue> {
    let cursor = Cursor::new(input.to_vec());
    let mut reader = SegmentedLzmaReader::new(cursor)
        .map_err(|e| JsValue::from_str(&format!("reader init failed: {}", e)))?;

    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| JsValue::from_str(&format!("read failed: {}", e)))?;

    Ok(out)
}

#[wasm_bindgen]
pub fn zlib_segmented_compress(input: &[u8]) -> Result<Vec<u8>, JsValue> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = SegmentedZlibWriter::new(cursor);

    writer
        .write_all(input)
        .map_err(|e| JsValue::from_str(&format!("write failed: {}", e)))?;

    let out_cursor = writer
        .finish()
        .map_err(|e| JsValue::from_str(&format!("finish failed: {}", e)))?;

    Ok(out_cursor.into_inner())
}

#[wasm_bindgen]
pub fn zlib_segmented_decompress(input: &[u8]) -> Result<Vec<u8>, JsValue> {
    let cursor = Cursor::new(input.to_vec());
    let mut reader = SegmentedZlibReader::new(cursor);

    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| JsValue::from_str(&format!("read failed: {}", e)))?;

    Ok(out)
}

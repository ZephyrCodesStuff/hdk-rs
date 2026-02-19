//! Export-related model structures and conversion logic
//!
//! This module defines export-friendly representations of the model data,
//! suitable for serialization to JSON. It includes methods to convert from
//! the raw binary model structures to these export formats.
//!
//! This is only enabled when the `export` feature is activated.

use crate::{Element, Material, Model, Texture, VertexStream};
use serde::Serialize;

/// Export-friendly model representation used for JSON output.
#[derive(Serialize)]
pub struct ExportModel {
    pub tag: u32,
    pub skeleton_key: u32,
    pub joint_count: u32,
    pub elements: Vec<ExportElement>,
    pub materials: Vec<ExportMaterial>,
    pub bounds: [f32; 4],
}

/// Export-friendly element representation used for JSON output.
#[derive(Serialize)]
pub struct ExportElement {
    pub name_hash: u32,
    pub primitive_type: u32,
    pub num_vertices: u32,
    pub vertex_stride: u32,
    pub material_hash: u32,
    pub flags: u32,
    pub end_lod_node_index: i16,
    pub vertex_streams: Vec<ExportVertexStream>,
    pub mesh: Option<ExportMesh>,
}

/// Export-friendly vertex stream representation.
#[derive(Serialize)]
pub struct ExportVertexStream {
    pub name_hash: u32,
    pub offset: u8,
    pub vertex_type: String,
    pub size: u8,
    pub normalized: bool,
}

/// Export-friendly mesh representation used for JSON output.
#[derive(Serialize)]
pub struct ExportMesh {
    pub num_indices: u32,
    pub num_vertices: u32,
    pub vertex_stride: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub positions: Option<Vec<[f32; 3]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indices: Option<Vec<u16>>,
}

/// Export-friendly material representation.
#[derive(Serialize)]
pub struct ExportMaterial {
    pub filename: String,
    pub material_hash: u32,
    pub material_instance_hash: u32,
    pub constant_hashes: Vec<u32>,
    pub constant_data: Vec<f32>,
    pub texture_hashes: Vec<u32>,
    pub textures: Vec<ExportTexture>,
    pub render_state_bits: u32,
    pub source_blend_func: u16,
    pub dest_blend_func: u16,
    pub alpha_test_func: u32,
    pub alpha_test_ref: f32,
}

/// Export-friendly texture representation.
#[derive(Serialize)]
pub struct ExportTexture {
    pub filename: String,
    pub wrap_bits: u32,
    pub border_colour: u32,
    pub lod_min: f32,
    pub lod_max: f32,
    pub lod_bias: f32,
}

impl Model {
    /// Converts the raw binary model into the friendly JSON-export struct
    pub fn to_export(&self) -> ExportModel {
        ExportModel {
            tag: self.tag,
            skeleton_key: self.skeleton_key,
            joint_count: self.joint_count,
            bounds: self.bounds,
            elements: self
                .elements
                .iter()
                .map(|e| e.to_export_element())
                .collect(),
            materials: self
                .materials
                .iter()
                .map(|m| m.to_export_material())
                .collect(),
        }
    }
}

impl Element {
    /// Convenience to get indices as u16
    pub fn get_indices(&self) -> Option<Vec<u16>> {
        if self.indices.is_empty() {
            return None;
        }
        Some(self.indices.clone())
    }

    /// Convenience to get positions (assuming stride >= 12 and f32x3 at offset 0)
    pub fn get_positions(&self) -> Option<Vec<[f32; 3]>> {
        if self.vertex_data.is_empty() {
            return None;
        }
        let stride = self.vertex_stride as usize;
        if stride < 12 {
            return None;
        }

        (0..self.num_vertices as usize)
            .map(|i| {
                let start = i * stride;
                let b = &self.vertex_data[start..start + 12];
                Some([
                    f32::from_be_bytes(b[0..4].try_into().ok()?),
                    f32::from_be_bytes(b[4..8].try_into().ok()?),
                    f32::from_be_bytes(b[8..12].try_into().ok()?),
                ])
            })
            .collect()
    }

    /// Converts to the friendly JSON-export struct
    pub fn to_export_element(&self) -> ExportElement {
        let has_mesh = !self.indices.is_empty() && self.num_vertices > 0;

        let mesh = if has_mesh {
            Some(ExportMesh {
                num_indices: self.indices.len() as u32,
                num_vertices: self.num_vertices,
                vertex_stride: self.vertex_stride,
                positions: self.get_positions(),
                indices: self.get_indices(),
            })
        } else {
            None
        };

        ExportElement {
            name_hash: self.name_hash,
            primitive_type: self.primitive_type,
            num_vertices: self.num_vertices,
            vertex_stride: self.vertex_stride,
            material_hash: self.material_hash,
            flags: self.flags,
            end_lod_node_index: self.end_lod_node_index,
            vertex_streams: self
                .vertex_streams
                .iter()
                .map(|vs| vs.to_export())
                .collect(),
            mesh,
        }
    }
}

impl VertexStream {
    pub fn to_export(&self) -> ExportVertexStream {
        ExportVertexStream {
            name_hash: self.name_hash,
            offset: self.offset,
            vertex_type: format!("{:?}", self.vertex_type),
            size: self.size,
            normalized: self.normalized,
        }
    }
}

impl Material {
    pub fn to_export_material(&self) -> ExportMaterial {
        ExportMaterial {
            filename: self.filename.clone(),
            material_hash: self.material_hash,
            material_instance_hash: self.material_instance_hash,
            constant_hashes: self.constant_hashes.clone(),
            constant_data: self.constant_data.clone(),
            texture_hashes: self.texture_hashes.clone(),
            textures: self.textures.iter().map(|t| t.to_export()).collect(),
            render_state_bits: self.render_state_bits,
            source_blend_func: self.source_blend_func,
            dest_blend_func: self.dest_blend_func,
            alpha_test_func: self.alpha_test_func,
            alpha_test_ref: self.alpha_test_ref,
        }
    }
}

impl Texture {
    pub fn to_export(&self) -> ExportTexture {
        ExportTexture {
            filename: self.filename.clone(),
            wrap_bits: self.wrap_bits,
            border_colour: self.border_colour,
            lod_min: self.lod_min,
            lod_max: self.lod_max,
            lod_bias: self.lod_bias,
        }
    }
}

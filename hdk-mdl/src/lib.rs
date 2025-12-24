#[cfg(feature = "export")]
mod export;

use binrw::{BinRead, NullString, binread};
use std::fmt::Debug;
use std::io::{Read, Seek, SeekFrom};

#[cfg(feature = "export")]
use serde::{Deserialize, Serialize};

/// A relative pointer that reads a 32-bit offset from the current position,
/// then seeks to (current_pos + offset) to read the target value.
/// This matches the C# BinReader.ReadOffset() behavior.
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
pub struct RelPtr<T>(pub Option<T>);

impl<T: BinRead + 'static> BinRead for RelPtr<T>
where
    T::Args<'static>: Clone + Default,
{
    type Args<'a> = T::Args<'static>;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let ptr_pos = reader.stream_position()?;
        let offset = <u32>::read_options(reader, endian, ())?;
        let return_pos = reader.stream_position()?;

        // Offset of 0 typically means null/invalid
        if offset == 0 {
            return Ok(RelPtr(None));
        }

        // Calculate absolute target: ptr_pos + offset
        let target = ptr_pos + offset as u64;

        // Bounds check
        let file_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(return_pos))?;
        if target >= file_len {
            return Ok(RelPtr(None));
        }

        // Jump, read, restore
        reader.seek(SeekFrom::Start(target))?;
        let value_res = T::read_options(reader, endian, args);
        reader.seek(SeekFrom::Start(return_pos))?;

        match value_res {
            Ok(value) => Ok(RelPtr(Some(value))),
            Err(_) => Ok(RelPtr(None)),
        }
    }
}

impl<T: Debug> Debug for RelPtr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Reads a relative offset and returns the absolute address.
/// Used for calculating where to read data from.
#[derive(Debug, Clone, Copy)]
pub struct RelOffset(pub u64);

impl BinRead for RelOffset {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let ptr_pos = reader.stream_position()?;
        let offset = <u32>::read_options(reader, endian, ())?;
        Ok(RelOffset(ptr_pos + offset as u64))
    }
}

/// The main model structure representing the MDL file.
///
/// Header layout (matching C# BinReader):
/// - 0x00: tag (4 bytes - magic "HM" + version)
/// - 0x04: skeletonKey
/// - 0x08: jointCount  
/// - 0x0C: elements count
/// - 0x10: elements offset (relative pointer)
/// - 0x14: materials count
/// - 0x18: materials offset (relative pointer)
/// - 0x1C: bounds offset (relative pointer) -> 4 floats
/// - 0x20: (if version >= 1.2) lod count + offset
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Model {
    pub tag: u32,
    pub skeleton_key: u32,
    pub joint_count: u32,
    pub elements: Vec<Element>,
    pub materials: Vec<Material>,
    pub bounds: [f32; 4],
}

impl BinRead for Model {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let endian = binrw::Endian::Big; // MDL is always big-endian

        // 0x00: tag (includes magic and version)
        let tag = u32::read_options(reader, endian, ())?;

        // 0x04: skeletonKey
        let skeleton_key = u32::read_options(reader, endian, ())?;

        // 0x08: jointCount
        let joint_count = u32::read_options(reader, endian, ())?;

        // 0x0C: elements count
        let elements_count = u32::read_options(reader, endian, ())?;

        // 0x10: elements offset (relative pointer)
        let elements_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x14: materials count
        let materials_count = u32::read_options(reader, endian, ())?;

        // 0x18: materials offset (relative pointer)
        let materials_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x1C: bounds offset (relative pointer)
        let bounds_offset = RelOffset::read_options(reader, endian, ())?;

        // Read bounds (4 floats at bounds_offset)
        let header_end_pos = reader.stream_position()?;
        reader.seek(SeekFrom::Start(bounds_offset.0))?;
        let bounds: [f32; 4] = BinRead::read_options(reader, endian, ())?;

        // Read elements
        reader.seek(SeekFrom::Start(elements_offset.0))?;
        let mut elements = Vec::with_capacity(elements_count as usize);
        for _ in 0..elements_count {
            elements.push(Element::read_options(reader, endian, ())?);
        }

        // Read materials
        reader.seek(SeekFrom::Start(materials_offset.0))?;
        let mut materials = Vec::with_capacity(materials_count as usize);
        for _ in 0..materials_count {
            materials.push(Material::read_options(reader, endian, ())?);
        }

        reader.seek(SeekFrom::Start(header_end_pos))?;

        Ok(Model {
            tag,
            skeleton_key,
            joint_count,
            elements,
            materials,
            bounds,
        })
    }
}

/// Represents a mesh element within the model.
///
/// Layout (matching C# LoadElement):
/// - 0x00: nameHash
/// - 0x04: primitiveType
/// - 0x08: index count
/// - 0x0C: index offset (relative pointer) -> ushort[]
/// - 0x10: numVertices
/// - 0x14: vertexStride
/// - 0x18: vertex data offset (relative pointer)
/// - 0x1C: vertex stream count
/// - 0x20: vertex stream offset (relative pointer)
/// - 0x24: material offset (relative pointer) -> [offset, uint, materialHash]
/// - 0x28: int
/// - 0x2C: offset (relative pointer)
/// - 0x30: offset (relative pointer)
/// - 0x34: flags
/// - 0x38: offset (relative pointer)
/// - 0x3C: endLodNodeIndex (i16)
/// - 0x3E: padding (u16)
/// - 0x40: offset (relative pointer)
/// - 0x44: uint
/// - 0x48: offset (relative pointer)
/// Total: 0x4C (76 bytes)
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Element {
    pub name_hash: u32,
    pub primitive_type: u32,
    pub indices: Vec<u16>,
    pub num_vertices: u32,
    pub vertex_stride: u32,
    pub vertex_data: Vec<u8>,
    pub vertex_streams: Vec<VertexStream>,
    pub material_hash: u32,
    pub flags: u32,
    pub end_lod_node_index: i16,
}

impl BinRead for Element {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let endian = binrw::Endian::Big;

        // 0x00: nameHash
        let name_hash = u32::read_options(reader, endian, ())?;

        // 0x04: primitiveType
        let primitive_type = u32::read_options(reader, endian, ())?;

        // 0x08: index count
        let index_count = u32::read_options(reader, endian, ())?;

        // 0x0C: index offset (relative pointer)
        let index_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x10: numVertices
        let num_vertices = u32::read_options(reader, endian, ())?;

        // 0x14: vertexStride
        let vertex_stride = u32::read_options(reader, endian, ())?;

        // 0x18: vertex data offset (relative pointer)
        let vertex_data_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x1C: vertex stream count
        let vertex_stream_count = u32::read_options(reader, endian, ())?;

        // 0x20: vertex stream offset (relative pointer)
        let vertex_stream_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x24: material offset (relative pointer)
        let material_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x28: int (unused)
        let _unused_int = i32::read_options(reader, endian, ())?;

        // 0x2C: offset (relative pointer, unused)
        let _unused_offset1 = RelOffset::read_options(reader, endian, ())?;

        // 0x30: offset (relative pointer, unused)
        let _unused_offset2 = RelOffset::read_options(reader, endian, ())?;

        // 0x34: flags
        let flags = u32::read_options(reader, endian, ())?;

        // 0x38: offset (relative pointer, unused)
        let _unused_offset3 = RelOffset::read_options(reader, endian, ())?;

        // 0x3C: endLodNodeIndex (i16)
        let end_lod_node_index = i16::read_options(reader, endian, ())?;

        // 0x3E: padding (u16)
        let _padding = u16::read_options(reader, endian, ())?;

        // 0x40: offset (relative pointer, unused)
        let _unused_offset4 = RelOffset::read_options(reader, endian, ())?;

        // 0x44: uint (unused)
        let _unused_uint = u32::read_options(reader, endian, ())?;

        // 0x48: offset (relative pointer, unused)
        let _unused_offset5 = RelOffset::read_options(reader, endian, ())?;

        // Save position to restore after reading sub-data
        let element_end_pos = reader.stream_position()?;

        // Read indices from index_offset
        reader.seek(SeekFrom::Start(index_offset.0))?;
        let mut indices = Vec::with_capacity(index_count as usize);
        for _ in 0..index_count {
            indices.push(u16::read_options(reader, endian, ())?);
        }

        // Read vertex data from vertex_data_offset
        let vertex_data_size = (num_vertices * vertex_stride) as usize;
        reader.seek(SeekFrom::Start(vertex_data_offset.0))?;
        let mut vertex_data = vec![0u8; vertex_data_size];
        reader.read_exact(&mut vertex_data)?;

        // Read vertex streams from vertex_stream_offset
        reader.seek(SeekFrom::Start(vertex_stream_offset.0))?;
        let mut vertex_streams = Vec::with_capacity(vertex_stream_count as usize);
        for _ in 0..vertex_stream_count {
            vertex_streams.push(VertexStream::read_options(reader, endian, ())?);
        }

        // Read material hash from material_offset
        // C#: binReader3.ReadOffset(); binReader3.ReadUInt(); element.materialHash = binReader3.ReadUInt();
        reader.seek(SeekFrom::Start(material_offset.0))?;
        let _mat_offset = RelOffset::read_options(reader, endian, ())?;
        let _mat_uint = u32::read_options(reader, endian, ())?;
        let material_hash = u32::read_options(reader, endian, ())?;

        // Restore position for next element
        reader.seek(SeekFrom::Start(element_end_pos))?;

        Ok(Element {
            name_hash,
            primitive_type,
            indices,
            num_vertices,
            vertex_stride,
            vertex_data,
            vertex_streams,
            material_hash,
            flags,
            end_lod_node_index,
        })
    }
}

/// Vertex stream descriptor.
///
/// Layout (matching C# LoadVertexStream):
/// - 0x00: nameHash (u32)
/// - 0x04: offset (u8)
/// - 0x05: type (u8)
/// - 0x06: size (u8)
/// - 0x07: normalized (u8, bool)
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
#[binread]
#[br(big)]
#[derive(Debug)]
pub struct VertexStream {
    pub name_hash: u32,
    pub offset: u8,
    #[br(map = |v: u8| VertexType::from(v))]
    pub vertex_type: VertexType,
    pub size: u8,
    #[br(map = |v: u8| v != 0)]
    pub normalized: bool,
}

/// Vertex data types matching C# LoadVertexData switch cases.
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexType {
    /// Type 1: i16 normalized to [-1, 1] by dividing by 32767
    NormalizedShort,
    /// Type 2: f32
    Float,
    /// Type 4: u8 normalized to [0, 1] by dividing by 255
    NormalizedByte,
    /// Type 5: i16 (raw, not normalized)
    Short,
    /// Type 6: Packed 10-10-10-2 format (3 values from one i32)
    Packed1010102,
    /// Type 7: u8 (raw, not normalized)
    Byte,
    /// Unknown type
    Unknown(u8),
}

impl From<u8> for VertexType {
    fn from(v: u8) -> Self {
        match v {
            1 => VertexType::NormalizedShort,
            2 => VertexType::Float,
            4 => VertexType::NormalizedByte,
            5 => VertexType::Short,
            6 => VertexType::Packed1010102,
            7 => VertexType::Byte,
            _ => VertexType::Unknown(v),
        }
    }
}

/// Material data structure.
///
/// Layout (matching C# LoadMaterial):
/// - 0x00: filename offset (relative pointer) -> string
/// - 0x04: materialHash
/// - 0x08: materialInstanceHash
/// - 0x0C: constant count
/// - 0x10: constant hashes offset (relative pointer)
/// - 0x14: constant data offset (relative pointer)
/// - 0x18: texture count
/// - 0x1C: texture hashes offset (relative pointer)
/// - 0x20: textures offset (relative pointer)
/// - 0x24: renderStateBits
/// - 0x28: sourceBlendFunc (u16)
/// - 0x2A: destBlendFunc (u16)
/// - 0x2C: alphaTestFunc
/// - 0x30: alphaTestRef
/// - 0x34: material attributes offset (relative pointer)
/// - 0x38: 4x u32 (unused)
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Material {
    pub filename: String,
    pub material_hash: u32,
    pub material_instance_hash: u32,
    pub constant_hashes: Vec<u32>,
    pub constant_data: Vec<f32>,
    pub texture_hashes: Vec<u32>,
    pub textures: Vec<Texture>,
    pub render_state_bits: u32,
    pub source_blend_func: u16,
    pub dest_blend_func: u16,
    pub alpha_test_func: u32,
    pub alpha_test_ref: f32,
    pub material_attributes: Vec<MaterialAttribute>,
}

impl BinRead for Material {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let endian = binrw::Endian::Big;

        // 0x00: filename offset
        let filename_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x04: materialHash
        let material_hash = u32::read_options(reader, endian, ())?;

        // 0x08: materialInstanceHash
        let material_instance_hash = u32::read_options(reader, endian, ())?;

        // 0x0C: constant count
        let constant_count = u32::read_options(reader, endian, ())?;

        // 0x10: constant hashes offset
        let constant_hashes_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x14: constant data offset
        let constant_data_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x18: texture count
        let texture_count = u32::read_options(reader, endian, ())?;

        // 0x1C: texture hashes offset
        let texture_hashes_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x20: textures offset
        let textures_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x24: renderStateBits
        let render_state_bits = u32::read_options(reader, endian, ())?;

        // 0x28: sourceBlendFunc (u16)
        let source_blend_func = u16::read_options(reader, endian, ())?;

        // 0x2A: destBlendFunc (u16)
        let dest_blend_func = u16::read_options(reader, endian, ())?;

        // 0x2C: alphaTestFunc
        let alpha_test_func = u32::read_options(reader, endian, ())?;

        // 0x30: alphaTestRef
        let alpha_test_ref = f32::read_options(reader, endian, ())?;

        // 0x34: material attributes offset
        let attributes_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x38: 4x u32 (unused)
        let _unused1 = u32::read_options(reader, endian, ())?;
        let _unused2 = u32::read_options(reader, endian, ())?;
        let _unused3 = u32::read_options(reader, endian, ())?;
        let _unused4 = u32::read_options(reader, endian, ())?;

        // Save position to restore after reading sub-data
        let material_end_pos = reader.stream_position()?;

        // Read filename
        reader.seek(SeekFrom::Start(filename_offset.0))?;
        let filename_ns = NullString::read_options(reader, endian, ())?;
        let filename = filename_ns.to_string();

        // Read constant hashes
        reader.seek(SeekFrom::Start(constant_hashes_offset.0))?;
        let mut constant_hashes = Vec::with_capacity(constant_count as usize);
        for _ in 0..constant_count {
            constant_hashes.push(u32::read_options(reader, endian, ())?);
        }

        // Read constant data (4 floats per constant)
        reader.seek(SeekFrom::Start(constant_data_offset.0))?;
        let mut constant_data = Vec::with_capacity((constant_count * 4) as usize);
        for _ in 0..(constant_count * 4) {
            constant_data.push(f32::read_options(reader, endian, ())?);
        }

        // Read texture hashes
        reader.seek(SeekFrom::Start(texture_hashes_offset.0))?;
        let mut texture_hashes = Vec::with_capacity(texture_count as usize);
        for _ in 0..texture_count {
            texture_hashes.push(u32::read_options(reader, endian, ())?);
        }

        // Read textures
        reader.seek(SeekFrom::Start(textures_offset.0))?;
        let mut textures = Vec::with_capacity(texture_count as usize);
        for _ in 0..texture_count {
            textures.push(Texture::read_options(reader, endian, ())?);
        }

        // Read material attributes if offset is non-zero
        let mut material_attributes = Vec::new();
        // Check if offset points somewhere valid (non-zero offset value)
        let attr_check_offset = attributes_offset.0;
        if attr_check_offset > 0 {
            reader.seek(SeekFrom::Start(attr_check_offset))?;
            let attr_count = u32::read_options(reader, endian, ())?;
            material_attributes.reserve(attr_count as usize);
            for _ in 0..attr_count {
                material_attributes.push(MaterialAttribute::read_options(reader, endian, ())?);
            }
        }

        // Restore position
        reader.seek(SeekFrom::Start(material_end_pos))?;

        Ok(Material {
            filename,
            material_hash,
            material_instance_hash,
            constant_hashes,
            constant_data,
            texture_hashes,
            textures,
            render_state_bits,
            source_blend_func,
            dest_blend_func,
            alpha_test_func,
            alpha_test_ref,
            material_attributes,
        })
    }
}

/// Texture data structure.
///
/// Layout (matching C# LoadTexture):
/// - 0x00: filename offset (relative pointer) -> string
/// - 0x04: wrapBits
/// - 0x08: borderColour
/// - 0x0C: lodMin
/// - 0x10: lodMax
/// - 0x14: lodBias
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Texture {
    pub filename: String,
    pub wrap_bits: u32,
    pub border_colour: u32,
    pub lod_min: f32,
    pub lod_max: f32,
    pub lod_bias: f32,
}

impl BinRead for Texture {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let endian = binrw::Endian::Big;

        // 0x00: filename offset
        let filename_offset = RelOffset::read_options(reader, endian, ())?;

        // 0x04: wrapBits
        let wrap_bits = u32::read_options(reader, endian, ())?;

        // 0x08: borderColour
        let border_colour = u32::read_options(reader, endian, ())?;

        // 0x0C: lodMin
        let lod_min = f32::read_options(reader, endian, ())?;

        // 0x10: lodMax
        let lod_max = f32::read_options(reader, endian, ())?;

        // 0x14: lodBias
        let lod_bias = f32::read_options(reader, endian, ())?;

        // Save position and read filename
        let texture_end_pos = reader.stream_position()?;

        reader.seek(SeekFrom::Start(filename_offset.0))?;
        let filename_ns = NullString::read_options(reader, endian, ())?;
        let filename = filename_ns.to_string();

        reader.seek(SeekFrom::Start(texture_end_pos))?;

        Ok(Texture {
            filename,
            wrap_bits,
            border_colour,
            lod_min,
            lod_max,
            lod_bias,
        })
    }
}

/// Material attribute structure.
#[cfg_attr(feature = "export", derive(Serialize, Deserialize))]
#[binread]
#[br(big)]
#[derive(Debug)]
pub struct MaterialAttribute {
    pub name: u32,
    pub data: u32,
}

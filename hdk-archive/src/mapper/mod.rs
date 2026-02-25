//! Mapper module for recovering original file paths from hashed files.
//!
//! This module provides functionality to map files named by their AfsHash
//! values back to their original paths. This is useful for recovering files
//! from HDK archives, since the original file paths are not stored in the archive
//! and only their hashes are available.
//!
//! The `Mapper` struct allows you to specify an input folder containing
//! hashed files, an optional output folder for the mapped files, and various
//! options to customize the mapping process.
//!
//! It uses regex patterns to scan file contents for potential original paths,
//! compute their hashes, and match them against the files in the input folder.
//!
//! # Example
//!
//! ```rust
//! use hdk_archive::mapper::Mapper;
//! use std::path::PathBuf;
//!
//! let input_folder = PathBuf::from("path/to/hashed_files");
//! let output_folder = PathBuf::from("path/to/mapped_files");
//!
//! let result = Mapper::new(input_folder)
//!     .with_output_folder(output_folder) // optional
//!     .with_full(true) // optional, enables slower patterns
//!     .run();
//!
//! println!("Mapped {} files, {} not found.", result.mapped, result.not_found.len());
//! ```

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use hdk_secure::hash::AfsHash;
use fancy_regex::{Regex, RegexBuilder};

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// Fast regex patterns always used for finding file paths in UTF-8 data.
pub const FAST_PATTERNS: [&str; 4] = [
    r#"(?:[\-\w\s]+\\)+[\-\w\s]+\.dds"#,
    r#"(?:file:\/+)*(?:(?:[\w-]+\/)+[\.\w-]+\.\w+)+"#,
    r#"\w+\.(?:ani|atmos|bar|bin|bnk|cdata|dds|efx|fnt|hkx|lua|luac|mdl|mp3|png|probe|scene|schema|skn|sharc|sho|sql|txt|xml|DDS)+"#,
    r#"source="(?:\S+)"#,
];

/// Slower regex patterns, only used when "full" mode is enabled.
pub const SLOW_PATTERNS: [&str; 1] = [
    // Original vs simplified

    // r#"(?<=\b(?<=source="|file="|texture\s=\s"|spriteTexture\s=\s\"))[^"]*"#,
    r#"\b(?:source=|file=|texture\s=\s|spriteTexture\s=\s)"([^"]*)"#,
    // Original vs simplified
    // Kinda unnecessary

    // r#"(?i)(\w+\.{{1}}(?=ani|atmos|bar|bin|bnk|cdata|dds|efx|fnt|hkx|lua|luac|mdl|mp3|png|probe|scene|schema|skn|sharc|sho|sql|txt|xml|DDS)\w)\w+"#,
    // r#"\w+\.(ani|atmos|bar|bin|bnk|cdata|dds|efx|fnt|hkx|lua|luac|mdl|mp3|png|probe|scene|schema|skn|sharc|sho|sql|txt|xml)\b"#,
];

/// Common scene file extensions to help with mapping variations.
pub const SCENE_EXTENSIONS: [&str; 25] = [
    "ani", "atmos", "atmosdev", "bar", "bin", "bnk", "cdata", "dds", "efx", "fnt", "hkx", "lua",
    "luac", "mdl", "mp3", "png", "probe", "scene", "schema", "skn", "sharc", "sho", "sql", "txt",
    "xml",
];

/// Common files that most objects / scenes contain.
pub const COMMON_FILES: [&str; 11] = [
    "catalogueentry.xml",
    "localisation.xml",
    "resources.xml",
    "screens.xml",
    "object.odc",
    "object.xml",
    "editor.oxml",
    "maker.png",
    "large.png",
    "small.png",
    "files.txt",
];

/// Get a map of common mappings that are generally available.
///
/// If a UUID is provided, it will also include UUID-prefixed versions of these common files.
pub fn get_common_mappings(uuid: Option<&str>) -> HashMap<AfsHash, String> {
    let mut hashes = HashMap::new();

    for file_path in COMMON_FILES.iter() {
        let s = file_path.to_string();
        let hash = AfsHash::new_from_str(&s);

        hashes.insert(hash, s);
    }

    if let Some(uuid) = uuid {
        for file_path in COMMON_FILES.iter() {
            let s = format!("Objects/{uuid}/{}", file_path);
            let hash = AfsHash::new_from_str(&s);

            hashes.insert(hash, s);
        }
    }

    hashes
}

/// Scans the given content for potential file paths and generates a map of their hashes.
///
/// This function uses regex patterns to find strings that look like file paths,
/// computes their [AfsHash] values, and returns a map from hash to original path string.
///
/// If a UUID is provided, it will also generate UUID-prefixed versions of found paths.
///
/// If `full` is enabled, additional (slower) regex patterns are used.
pub fn scan_content_for_paths(
    content: &[u8],
    uuid: Option<&str>,
    regexes: &[Regex], // Pass pre-compiled regexes here
) -> HashMap<AfsHash, String> {
    let data_str = String::from_utf8_lossy(content);
    let mut local_matches = HashMap::new();

    for regex in regexes {
        let matches = regex.find_iter(&data_str).filter_map(|m| m.ok());

        for m in matches {
            let mut raw = m.as_str().to_string();

            if raw.contains('"') {
                if let (Some(s), Some(e)) = (raw.find('"'), raw.rfind('"'))
                    && e > s
                {
                    raw = raw[s + 1..e].to_string();
                }
            } else {
                raw = raw
                    .trim()
                    .trim_start_matches("source=")
                    .trim_start_matches("file=")
                    .trim()
                    .to_string();
            }

            let path_str = raw
                .to_lowercase()
                .replace("\\", "/")
                .replace("file:///resource_root/build/", "")
                .replace("file://resource_root/build/", "");

            // Variants logic
            if let Some(base) = SCENE_EXTENSIONS
                .iter()
                .find_map(|ext| path_str.strip_suffix(format!(".{ext}").as_str()))
            {
                for extension in SCENE_EXTENSIONS.iter() {
                    let scene_val = format!("{base}.{extension}");
                    let hashed_val = AfsHash::new_from_str(&scene_val);
                    local_matches.insert(hashed_val, scene_val.clone());

                    if let Some(uuid) = uuid {
                        let scene_uuid = format!("Objects/{uuid}/{scene_val}");
                        local_matches.insert(AfsHash::new_from_str(&scene_uuid), scene_uuid);
                    }
                }
                let extras_val = format!("{base}_extras.scene");
                local_matches.insert(AfsHash::new_from_str(&extras_val), extras_val);
            }

            local_matches.insert(AfsHash::new_from_str(&path_str), path_str.clone());

            if let Some(uuid) = uuid {
                let uuid_path = format!("Objects/{uuid}/{path_str}");
                local_matches.insert(AfsHash::new_from_str(&uuid_path), uuid_path);
            }
        }
    }

    local_matches
}

/// Result returned by `Mapper::run` containing summary information.
pub struct MappingResult {
    pub mapped: usize,
    pub not_found: Vec<PathBuf>,
}

/// Builder for mapping hashed files back to their original paths.
///
/// This is primarily useful for recovering files from HDK archives,
/// where file paths are stored as AfsHash values and thus lost.
///
/// # Example
///
/// ```rust
/// use hdk_archive::mapper::Mapper;
/// use std::path::PathBuf;
///
/// let input_folder = PathBuf::from("path/to/hashed_files");
/// let output_folder = PathBuf::from("path/to/mapped_files");
///
/// let result = Mapper::new(input_folder)
///     .with_output_folder(output_folder) // optional
///     .with_full(true) // optional, enables slower patterns
///     .run();
///
/// println!("Mapped {} files, {} not found.", result.mapped, result.not_found.len());
/// ```
pub struct Mapper {
    input_folder: PathBuf,
    output_folder: Option<PathBuf>,
    uuid: Option<String>,
    full: bool,
    extra_files: Vec<PathBuf>,
}

impl Mapper {
    /// Create a new `Mapper` for the given input folder.
    ///
    /// The input folder should contain files named by their AfsHash values.
    ///
    /// # Notes
    ///
    /// Set an output folder via [Mapper::with_output_folder] to specify where mapped files should be written.
    ///
    /// If not set, defaults to a sibling folder named `{input_folder}_mapped`.
    pub const fn new(input_folder: PathBuf) -> Self {
        Self {
            input_folder,
            output_folder: None,
            uuid: None,
            full: false,
            extra_files: Vec::new(),
        }
    }

    /// Set the output folder for mapped files.
    pub fn with_output_folder(mut self, output: PathBuf) -> Self {
        self.output_folder = Some(output);
        self
    }

    /// Set the UUID to use when mapping files within an object's folder.
    ///
    /// This is required for Objects since their original hashes
    /// did take a prefix of `Objects/{UUID}/` into account when hashing.
    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Enable full mapping mode, which includes slower regex patterns.
    pub const fn with_full(mut self, full: bool) -> Self {
        self.full = full;
        self
    }

    /// Add an extra file to be considered for mapping.
    ///
    /// This can serve as a source of additional paths to hash beyond those found in the input folder.
    ///
    /// For example, you may want to add a binary file that just so happens to use the files you're trying to map.
    pub fn with_extra_file(mut self, path: PathBuf) -> Self {
        self.extra_files.push(path);
        self
    }

    /// Add multiple extra files to be considered for mapping.
    ///
    /// See [Mapper::with_extra_file] for more details.
    pub fn with_extra_files<I: IntoIterator<Item = PathBuf>>(mut self, paths: I) -> Self {
        self.extra_files.extend(paths);
        self
    }

    /// Run the mapping process and return a summary `MappingResult`.
    pub fn run(self) -> MappingResult {
        let Self { ref input_folder, output_folder: ref builder_output, ref uuid, full, ref extra_files } = self;

        // 1. Collect all paths (Serial is fine for metadata scan)
        let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(input_folder)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        paths.extend(extra_files.iter().filter(|p| p.is_file()).cloned());
        
        if paths.is_empty() {
            return MappingResult { mapped: 0, not_found: Vec::new() };
        }

        // 2. Pre-compile Regexes ONCE
        let mut patterns = FAST_PATTERNS.iter().map(|&x| x.to_string()).collect::<Vec<_>>();
        if full { patterns.extend(SLOW_PATTERNS.iter().map(|&x| x.to_string())); }
        
        let compiled_regexes: Vec<Regex> = patterns.iter().map(|p| {
            RegexBuilder::new(p).backtrack_limit(usize::MAX).build().unwrap()
        }).collect();

        // 3. Parallel Scanning Phase
        #[cfg(feature = "rayon")]
        let discovered_mappings = {
            paths.par_iter()
                .filter_map(|p| std::fs::read(p).ok())
                .fold(HashMap::new, |mut acc, buf| {
                    let matches = scan_content_for_paths(&buf, uuid.as_deref(), &compiled_regexes);
                    acc.extend(matches);
                    acc
                })
                .reduce(HashMap::new, |mut a, b| { a.extend(b); a })
        };

        #[cfg(not(feature = "rayon"))]
        let discovered_mappings = {
            let mut acc = HashMap::new();
            for p in &paths {
                if let Ok(buf) = std::fs::read(p) {
                    acc.extend(scan_content_for_paths(&buf, uuid.as_deref(), &compiled_regexes));
                }
            }
            acc
        };

        // 4. Merge with Static Mappings
        let mut final_hashes = get_common_mappings(uuid.as_deref());
        for (k, v) in discovered_mappings {
            final_hashes.insert(k, v);
        }

        // 5. Prepare Output
        let output_folder: PathBuf = builder_output
            .as_ref()
            .cloned()
            .unwrap_or_else(|| {
                let folder_name = input_folder.file_name().unwrap().to_str().unwrap();
                input_folder
                    .parent()
                    .unwrap()
                    .join(self.output_folder.clone().unwrap_or_else(|| format!("{}_mapped", folder_name).into()))
            });

        // 6. Parallel Mapping (File Copy) Phase
        // Moving files and creating dirs in parallel is much faster on NVMe
        let file_count = paths.len();
        
        #[cfg(feature = "rayon")]
        let not_found_list: Vec<PathBuf> = {
            paths.into_par_iter()
                .filter_map(|path| {
                    self.process_single_file(&path, &output_folder, &final_hashes)
                })
                .collect()
        };

        #[cfg(not(feature = "rayon"))]
        let not_found_list: Vec<PathBuf> = {
            paths.into_iter()
                .filter_map(|path| self.process_single_file(&path, &output_folder, &final_hashes))
                .collect()
        };

        MappingResult {
            mapped: file_count - not_found_list.len(),
            not_found: not_found_list,
        }
    }

    /// Helper to process a single file mapping
    fn process_single_file(&self, path: &Path, output_folder: &Path, hashes: &HashMap<AfsHash, String>) -> Option<PathBuf> {
        let hash_str = path.file_name()?.to_str()?;
        if !AfsHash::is_valid_hash_str(hash_str) { return None; }

        let hash_val = u32::from_str_radix(hash_str, 16).ok()?;
        let hash = AfsHash(hash_val as i32);

        if let Some(recovered_path) = hashes.get(&hash) {
            let output_path = output_folder.join(recovered_path);
            let _ = std::fs::create_dir_all(output_path.parent().unwrap());
            if std::fs::copy(path, &output_path).is_ok() {
                return None;
            }
        }
        
        Some(path.to_path_buf())
    }
}

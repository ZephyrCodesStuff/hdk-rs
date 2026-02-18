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
    path::PathBuf,
    sync::{RwLock, atomic::AtomicUsize},
};

use hdk_secure::hash::AfsHash;

/// Fast regex patterns always used for finding file paths in UTF-8 data.
const FAST_PATTERNS: [&str; 4] = [
    r#"(?:[\-\w\s]+\\)+[\-\w\s]+\.dds"#,
    r#"(?:file:\/+)*(?:(?:[\w-]+\/)+[\.\w-]+\.\w+)+"#,
    r#"\w+\.(?:ani|atmos|bar|bin|bnk|cdata|dds|efx|fnt|hkx|lua|luac|mdl|mp3|png|probe|scene|schema|skn|sharc|sho|sql|txt|xml|DDS)+"#,
    r#"source="(?:\S+)"#,
];

/// Slower regex patterns, only used when "full" mode is enabled.
const SLOW_PATTERNS: [&str; 1] = [
    // Original vs simplified

    // r#"(?<=\b(?<=source="|file="|texture\s=\s"|spriteTexture\s=\s\"))[^"]*"#,
    r#"\b(?:source=|file=|texture\s=\s|spriteTexture\s=\s)"([^"]*)"#,
    // Original vs simplified
    // Kinda unnecessary

    // r#"(?i)(\w+\.{{1}}(?=ani|atmos|bar|bin|bnk|cdata|dds|efx|fnt|hkx|lua|luac|mdl|mp3|png|probe|scene|schema|skn|sharc|sho|sql|txt|xml|DDS)\w)\w+"#,
    // r#"\w+\.(ani|atmos|bar|bin|bnk|cdata|dds|efx|fnt|hkx|lua|luac|mdl|mp3|png|probe|scene|schema|skn|sharc|sho|sql|txt|xml)\b"#,
];

/// Common scene file extensions to help with mapping variations.
const SCENE_EXTENSIONS: [&str; 26] = [
    "ani",
    "atmos",
    "atmosdev",
    "bar",
    "bin",
    "bnk",
    "cdata",
    "dds",
    "efx",
    "fnt",
    "hkx",
    "lua",
    "luac",
    "mdl",
    "mp3",
    "png",
    "probe",
    "scene",
    "scene_extras",
    "schema",
    "skn",
    "sharc",
    "sho",
    "sql",
    "txt",
    "xml",
];

/// Common files that most objects / scenes contain.
const COMMON_FILES: [&str; 11] = [
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
        let Self {
            input_folder,
            output_folder: builder_output,
            uuid,
            full,
            extra_files,
        } = self;

        // Load all files in the input folder
        let mut paths: Vec<PathBuf> = Vec::new();

        let result = (|| -> Result<(), walkdir::Error> {
            for entry in walkdir::WalkDir::new(&input_folder).into_iter() {
                let entry = entry?;

                if !entry.path().is_file() {
                    continue;
                }

                paths.push(entry.path().to_path_buf());
            }

            Ok(())
        })();

        if result.is_err() {
            println!("Failed to read folder {}!", input_folder.display());
            return MappingResult {
                mapped: 0,
                not_found: Vec::new(),
            };
        }

        // Add any extra files provided via builder
        for path in extra_files {
            if path.exists() && path.is_file() {
                println!("Reading additional file {}", path.display());
                paths.push(path);
            } else {
                println!("Could not read additional file {}", path.display());
            }
        }

        let file_count = paths.len() as u64;

        if file_count == 0 {
            println!("No files found in the folder!");
            return MappingResult {
                mapped: 0,
                not_found: Vec::new(),
            };
        }

        let hashes = RwLock::new(HashMap::new());

        // insert static hashes for files that do not get referenced (therefore can't be detected)
        // Use the same string-based normalization used for matches so hashing is consistent.
        {
            for file_path in COMMON_FILES.iter() {
                let s = file_path.to_string();
                let hash = AfsHash::new_from_str(&s);

                hashes.write().unwrap().insert(hash, PathBuf::from(s));
            }

            if let Some(uuid) = &uuid {
                for file_path in COMMON_FILES.iter() {
                    let s = format!("Objects/{uuid}/{}", file_path);
                    let hash = AfsHash::new_from_str(&s);

                    hashes.write().unwrap().insert(hash, PathBuf::from(s));
                }
            }
        }

        // Always scan fast patterns, optionally scan slow patterns
        let mut patterns = FAST_PATTERNS
            .iter()
            .map(|&x| x.to_string())
            .collect::<Vec<String>>();

        if full {
            patterns.extend(SLOW_PATTERNS.iter().map(|&x| x.to_string()));
        }

        // Precompile regexes for better performance
        let compiled_regexes: Vec<fancy_regex::Regex> = patterns
            .iter()
            .map(|pattern| {
                fancy_regex::RegexBuilder::new(pattern)
                    .backtrack_limit(usize::MAX)
                    .build()
                    .unwrap()
            })
            .collect();

        // Use a shared map to accumulate found mappings
        let result_hashes: RwLock<_> = RwLock::new(HashMap::new());

        for path in &paths {
            let buf: Vec<u8> = match std::fs::read(path) {
                Ok(content) => content,
                Err(_) => continue,
            };

            let data_str = String::from_utf8_lossy(&buf);

            let mut local_matches = HashMap::new();

            for regex in &compiled_regexes {
                let matches: Vec<_> = regex.find_iter(&data_str).filter_map(|m| m.ok()).collect();

                for m in matches {
                    // Start with the raw match string and try to extract the actual path
                    let mut raw = m.as_str().to_string();

                    // If the match contains quoted content, extract the part between the first and last quote
                    if raw.contains('"') {
                        if let (Some(s), Some(e)) = (raw.find('"'), raw.rfind('"'))
                            && e > s
                        {
                            raw = raw[s + 1..e].to_string();
                        }
                    } else {
                        // Remove common leading tokens like `source=` or `file=` and trim
                        raw = raw
                            .trim()
                            .trim_start_matches("source=")
                            .trim_start_matches("file=")
                            .trim()
                            .to_string();
                    }

                    // Normalize slashes and lowercase (matches are compared against string-hashed entries)
                    let path_str = raw
                        .to_lowercase()
                        .replace("\\", "/")
                        .replace("file:///resource_root/build/", "")
                        .replace("file://resource_root/build/", "");

                    // Generate scene extension variants for the plain path (non-UUID)
                    if let Some(base) = SCENE_EXTENSIONS
                        .iter()
                        .find_map(|ext| path_str.strip_suffix(ext))
                    {
                        for extension in SCENE_EXTENSIONS.iter() {
                            let scene_val = format!("{base}{extension}");
                            let hashed_val = AfsHash::new_from_str(&scene_val);
                            local_matches.insert(hashed_val, scene_val.clone());

                            // Also insert UUID-prefixed variant so object-scoped hashes match
                            if let Some(uuid) = &uuid {
                                let scene_uuid = format!("Objects/{uuid}/{scene_val}");
                                let hashed_uuid = AfsHash::new_from_str(&scene_uuid);
                                local_matches.insert(hashed_uuid, scene_uuid);
                            }
                        }
                    }

                    // Insert the plain path
                    let hash_plain = AfsHash::new_from_str(&path_str);
                    local_matches.insert(hash_plain, path_str.clone());

                    // If mapping an object, also insert the UUID-prefixed path variant
                    if let Some(uuid) = &uuid {
                        let uuid_path = format!("Objects/{uuid}/{path_str}");
                        let hash_uuid = AfsHash::new_from_str(&uuid_path);
                        local_matches.insert(hash_uuid, uuid_path);
                    }
                }
            }

            {
                let mut shared_hashes = result_hashes.write().unwrap();
                for (key, value) in local_matches {
                    shared_hashes.insert(key, value);
                }
            }
        }

        // Merge the results into the main hashes map
        {
            let mut main_hashes = hashes.write().unwrap();
            let shared_results = result_hashes.read().unwrap();

            for (k, v) in shared_results.iter() {
                main_hashes.insert(*k, v.into());
            }
        }

        // Check if we found any hashes
        if hashes.read().unwrap().is_empty() {
            return MappingResult {
                mapped: 0,
                not_found: Vec::new(),
            };
        }

        // Prepare output folder
        let output_folder = builder_output.unwrap_or_else(|| {
            let mut output = input_folder.clone();
            let folder_name = input_folder.file_name().unwrap().to_str().unwrap();

            output = output
                .parent()
                .unwrap()
                .join(format!("{folder_name}_mapped"));

            output
        });

        // Actually write the mapped files
        let found: AtomicUsize = AtomicUsize::new(0);
        let not_found = RwLock::new(Vec::new());

        for path in &paths {
            let hash_str = path.file_name().unwrap().to_str().unwrap().to_owned();
            println!(
                "Mapping file {}/{}: {}",
                found.load(std::sync::atomic::Ordering::Relaxed) + 1,
                file_count,
                hash_str
            );

            if !AfsHash::is_valid_hash_str(&hash_str) {
                continue;
            }

            let hash_val = u32::from_str_radix(&hash_str, 16).unwrap();
            let hash = AfsHash(hash_val as i32);
            let recovered_path = {
                let rw = hashes.read().unwrap();
                match rw.get(&hash) {
                    Some(p) => p.clone(),
                    None => {
                        println!("[!] Could not find mapping for file {}", path.display());
                        not_found.write().unwrap().push(path.clone());
                        continue;
                    }
                }
            };

            let output_path = output_folder.join(recovered_path);
            std::fs::create_dir_all(output_path.parent().unwrap()).unwrap();

            // Note: apparently moving a file DOES NOT take less time than copying it..?
            std::fs::copy(path, &output_path).unwrap();

            found.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let found = found.load(std::sync::atomic::Ordering::Relaxed);

        // Copy .time file
        let time_file = input_folder.join(".time");
        if time_file.is_file() {
            let output_time_file = output_folder.join(".time");
            std::fs::copy(time_file, output_time_file).unwrap();
        } else {
            println!("No .time file found. Archive may fail to mount! (SEC error -6 in logs)");
        }

        MappingResult {
            mapped: found,
            not_found: not_found.into_inner().unwrap(),
        }
    }
}

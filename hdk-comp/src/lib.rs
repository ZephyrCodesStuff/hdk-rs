pub mod lzma;
pub mod zlib;

thread_local! {
    /// A 64KB+ buffer that lives for the life of the thread
    /// 
    /// We use this as scratch space for compression to avoid repeated allocations.
    /// 
    /// It's large enough to hold the largest possible compressed chunk,
    /// so it can be used for both compression and decompression.
    static COMPRESSION_SCRATCH: std::cell::RefCell<smallvec::SmallVec<[u8; 65536]>> = std::cell::RefCell::new(smallvec::SmallVec::new());
}
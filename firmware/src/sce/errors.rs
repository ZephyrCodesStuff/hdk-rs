use thiserror::Error;

#[derive(Debug, Error)]
pub enum SCEDecryptError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid SCE magic")]
    InvalidMagic,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid metadata")]
    InvalidMetadata,
}

#[derive(Debug, Error)]
pub enum SceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid SCE magic")]
    InvalidMagic,

    #[error("invalid metadata")]
    InvalidMetadata,

    #[error("section index out of range")]
    SectionIndex,

    #[error("section offsets out of bounds")]
    SectionOutOfBounds,
}

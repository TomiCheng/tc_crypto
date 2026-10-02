#[cfg(feature = "alloc")]
mod buffered_block_cipher;
mod fixed_buffered_block_cipher;
mod fixed_padded_buffered_block_cipher;
#[cfg(feature = "alloc")]
mod padded_buffered_block_cipher;
mod shared;

#[cfg(feature = "alloc")]
pub use buffered_block_cipher::BufferedBlockCipher;
pub use fixed_buffered_block_cipher::FixedBufferedBlockCipher;
pub use fixed_padded_buffered_block_cipher::FixedPaddedBufferedBlockCipher;
#[cfg(feature = "alloc")]
pub use padded_buffered_block_cipher::PaddedBufferedBlockCipher;

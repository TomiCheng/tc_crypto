use crate::CipherDirection;
use core::error::Error;

pub trait BufferedCipher {
    type Error: Error;

    fn block_size(&self) -> usize;

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.process_bytes(&[input], output)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    fn reset(&mut self);
}

pub trait BufferedCipherInit<P: ?Sized> {
    type Error: Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

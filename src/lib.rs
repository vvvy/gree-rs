mod apdu;
mod state;
pub mod sync_client;
pub mod async_client;


pub use apdu::{vars, vars::DEFAULT as DEFAULT_VARS};
pub use state::*;
pub use serde_json::Value;

use apdu::*;
use log::{trace, debug, error};

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

const GENERIC_KEY: &str = "a3K8Bx%2r8Y7#xDh";
const PORT: u16 = 7000;



/* 

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
*/
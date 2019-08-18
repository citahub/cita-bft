use crate::crypto::PrivKey;
use crate::types::clean_0x;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

#[derive(Debug, Deserialize, Clone)]
pub struct PrivateKey {
    pub signer: PrivKey,
}

impl PrivateKey {
    pub fn new(path: &str) -> Self {
        let mut buffer = String::new();
        File::open(path)
            .and_then(|mut f| f.read_to_string(&mut buffer))
            .unwrap_or_else(|err| panic!("Error while loading PrivateKey: [{}]", err));

        let signer = PrivKey::from_str(clean_0x(&buffer)).unwrap();

        PrivateKey { signer }
    }
}

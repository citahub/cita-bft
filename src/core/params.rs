// CITA
// Copyright 2016-2017 Cryptape Technologies LLC.

// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any
// later version.

// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

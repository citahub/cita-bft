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

use super::ntp::Ntp;
use crypto::{PrivKey, Signer};
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;
use types::clean_0x;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub ntp_config: Ntp,
    // cycle = propose + prevote + precommit + commit, in milliseconds.
    cycle: u64,
}

impl Config {
    pub fn new(path: &str) -> Self {
        parse_config!(Config, path)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrivateKey {
    signer: PrivKey,
}

impl PrivateKey {
    pub fn new(path: &str) -> Self {
        let mut buffer = String::new();
        File::open(path)
            .and_then(|mut f| f.read_to_string(&mut buffer))
            .unwrap_or_else(|err| panic!("Error while loading PrivateKey: [{}]", err));

        let signer = PrivKey::from_str(clean_0x(&buffer)).unwrap();

        PrivateKey { signer: signer }
    }
}

#[derive(Debug, Clone)]
pub struct TendermintTimer {
    pub propose: Duration,
    pub prevote: Duration,
    pub precommit: Duration,
    pub commit: Duration,
}

pub struct TendermintParams {
    pub timer: TendermintTimer,
    pub signer: Signer,
}

impl TendermintParams {
    pub fn new(config: &Config, priv_key: &PrivateKey) -> Self {
        TendermintParams {
            signer: Signer::from(priv_key.signer),
            timer: TendermintTimer {
                propose: Duration::from_millis(config.cycle * 24 / 30),
                prevote: Duration::from_millis(config.cycle * 1 / 30),
                precommit: Duration::from_millis(config.cycle * 1 / 30),
                commit: Duration::from_millis(config.cycle * 4 / 30),
            },
        }
    }
}

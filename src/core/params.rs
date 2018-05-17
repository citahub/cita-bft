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

    #[serde(rename = "timeoutPropose")] pub timeout_propose: Option<u64>,
    // Prevote step timeout in milliseconds.
    #[serde(rename = "timeoutPrevote")] pub timeout_prevote: Option<u64>,
    // Precommit step timeout in milliseconds.
    #[serde(rename = "timeoutPrecommit")] pub timeout_precommit: Option<u64>,
    // Commit step timeout in milliseconds.
    #[serde(rename = "timeoutCommit")] pub timeout_commit: Option<u64>,
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

impl Default for TendermintTimer {
    fn default() -> Self {
        TendermintTimer {
            propose: Duration::from_millis(2400),
            prevote: Duration::from_millis(100),
            precommit: Duration::from_millis(100),
            commit: Duration::from_millis(400),
        }
    }
}

pub struct TendermintParams {
    pub timer: TendermintTimer,
    pub signer: Signer,
}

fn to_duration(s: u64) -> Duration {
    Duration::from_millis(s)
}

impl TendermintParams {
    pub fn new(config: &Config, priv_key: &PrivateKey) -> Self {
        let dt = TendermintTimer::default();
        TendermintParams {
            signer: Signer::from(priv_key.signer),
            timer: TendermintTimer {
                propose: config.timeout_propose.map_or(dt.propose, to_duration),
                prevote: config.timeout_prevote.map_or(dt.prevote, to_duration),
                precommit: config.timeout_precommit.map_or(dt.precommit, to_duration),
                commit: config.timeout_commit.map_or(dt.commit, to_duration),
            },
        }
    }
}

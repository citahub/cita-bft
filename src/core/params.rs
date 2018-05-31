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
use std::cell::Cell;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;
use types::clean_0x;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub ntp_config: Ntp,
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
    total_duration: Cell<u64>,
    total_quota: u64,
    propose: u64,
    prevote: u64,
    precommit: u64,
    commit: u64,
}

impl Default for TendermintTimer {
    fn default() -> Self {
        TendermintTimer {
            // in milliseconds.
            total_duration: Cell::new(3000),
            //total_quota = propose + prevote + precommit + commit.
            total_quota: 30,
            propose: 24,
            prevote: 1,
            precommit: 1,
            commit: 4,
        }
    }
}

impl TendermintTimer {
    pub fn set_total_duration(&self, duration: u64) {
        self.total_duration.set(duration);
    }

    pub fn get_propose(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.propose / self.total_quota)
    }

    pub fn get_prevote(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.prevote / self.total_quota)
    }

    pub fn get_precommit(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.precommit / self.total_quota)
    }

    pub fn get_commit(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.commit / self.total_quota)
    }
}

pub struct TendermintParams {
    pub timer: TendermintTimer,
    pub signer: Signer,
}

impl TendermintParams {
    pub fn new(priv_key: &PrivateKey) -> Self {
        TendermintParams {
            signer: Signer::from(priv_key.signer),
            timer: TendermintTimer::default(),
        }
    }
}

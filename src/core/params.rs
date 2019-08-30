// Copyright 2019 Cryptape Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::crypto::{PrivKey, Signer};
use crate::types::clean_0x;
use std::cell::Cell;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;

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

        PrivateKey { signer }
    }
}

#[derive(Debug, Clone)]
pub struct BftTimer {
    // in milliseconds.
    total_duration: Cell<u64>,
    // fraction: (numerator, denominator)
    propose: (u64, u64),
    prevote: (u64, u64),
    precommit: (u64, u64),
    commit: (u64, u64),
}

impl Default for BftTimer {
    fn default() -> Self {
        BftTimer {
            total_duration: Cell::new(3000),
            propose: (24, 30),
            prevote: (1, 30),
            precommit: (1, 30),
            commit: (4, 30),
        }
    }
}

impl BftTimer {
    pub fn set_total_duration(&self, duration: u64) {
        self.total_duration.set(duration);
    }

    pub fn get_propose(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.propose.0 / self.propose.1)
    }

    pub fn get_prevote(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.prevote.0 / self.prevote.1)
    }

    pub fn get_precommit(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.precommit.0 / self.precommit.1)
    }

    pub fn get_commit(&self) -> Duration {
        Duration::from_millis(self.total_duration.get() * self.commit.0 / self.commit.1)
    }
}

pub struct BftParams {
    pub timer: BftTimer,
    pub signer: Signer,
}

impl BftParams {
    pub fn new(priv_key: &PrivateKey) -> Self {
        BftParams {
            signer: Signer::from(priv_key.signer),
            timer: BftTimer::default(),
        }
    }
}

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

//! ## Summary
//!
//! One of CITA's core components, implementation of variants of Bft consensus algorithm.
//! The entire process is driven by timeout mechanisms and voting.
//!
//! ### Message queuing situation
//!
//! 1. Subscribe channel
//!
//!     | Queue     | PubModule | Message Type          |
//!     | --------- | --------- | --------------------- |
//!     | consensus | Net       | CompactSignedProposal |
//!     | consensus | Net       | RawBytes              |
//!     | consensus | Chain     | RichStatus            |
//!     | consensus | Auth      | BlockTxs              |
//!     | consensus | Auth      | VerifyBlockResp       |
//!     | consensus | Snapshot  | SnapshotReq           |
//!
//! 2. Publish channel
//!
//!     | Queue     | PubModule | SubModule       | Message Type          |
//!     | --------- | --------- | --------------- | --------------------- |
//!     | consensus | Consensus | Auth            | VerifyBlockReq        |
//!     | consensus | Consensus | Net             | RawBytes              |
//!     | consensus | Consensus | Chain, Executor | BlockWithProof        |
//!     | consensus | Consensus | Net             | CompactSignedProposal |
//!     | consensus | Consensus | Executor        | SignedProposal        |
//!     | consensus | Consensus | Snapshot        | SnapshotResp          |
//!

extern crate authority_manage;
extern crate bft_rs as bft;
extern crate bincode;
extern crate cita_crypto as crypto;
extern crate cita_directories;
extern crate cita_types as types;
extern crate clap;
extern crate dotenv;
extern crate engine;
extern crate hashable;
extern crate min_max_heap;
#[macro_use]
extern crate libproto;
#[macro_use]
extern crate cita_logger as logger;
extern crate lru_cache;
extern crate proof;
extern crate pubsub;
extern crate rustc_hex;
#[macro_use]
extern crate serde_derive;
extern crate time;
#[macro_use]
extern crate util;

use bft::BftActuator;
use cita_directories::DataPath;
use clap::App;
use std::sync::Arc;
use std::thread;

mod core;
use crate::core::agent::{BftAgent, RabbitMqAgent};
use crate::core::bft_bridge::{BftBridge, Processor};
use crate::core::params::PrivateKey;
use crate::crypto::Signer;
use util::set_panic_handler;

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

fn main() {
    let matches = App::new("cita-bft")
        .version(get_build_info_str(true))
        .long_version(get_build_info_str(false))
        .author("Cryptape")
        .about("CITA Block Chain Node powered by Rust")
        .args_from_usage("-c, --config=[FILE] 'Sets a custom config file'")
        .args_from_usage("-p, --private=[FILE] 'Sets a private key file'")
        .args_from_usage(
            "--prof-start=[0] 'Specify the start time of profiling, zero means no profiling'",
        )
        .args_from_usage(
            "--prof-duration=[0] 'Specify the duration for profiling, zero means no profiling'",
        )
        .args_from_usage("-s, --stdout 'Log to console'")
        .get_matches();

    let stdout = matches.is_present("stdout");
    micro_service_init!("cita-bft", "CITA:consensus:cita-bft", stdout);
    info!("Version: {}", get_build_info_str(true));

    let mut pk_path = "privkey";
    if let Some(p) = matches.value_of("private") {
        pk_path = p;
    }
    let pk = PrivateKey::new(pk_path);
    let signer = Signer::from(pk.signer);

    let rabbitmq_agent = RabbitMqAgent::new();

    let main_thd = thread::spawn(move || {
        let bft_agent = BftAgent::new();
        let bridge = BftBridge::new(bft_agent.bft_server.clone());
        let bft_actuator = BftActuator::new(
            Arc::new(bridge),
            signer.address.to_vec().into(),
            &DataPath::wal_path(),
        );
        let mut processor = Processor::new(bft_agent.bft_client, rabbitmq_agent, bft_actuator, pk);
        processor.start();
    });

    main_thd.join().unwrap();
}

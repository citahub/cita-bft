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
extern crate cpuprofiler;
extern crate dotenv;
extern crate engine;
extern crate hashable;
extern crate min_max_heap;
#[macro_use]
extern crate libproto;
#[macro_use]
extern crate logger;
extern crate lru_cache;
extern crate ntp;
extern crate proof;
extern crate pubsub;
extern crate rustc_hex;
#[macro_use]
extern crate serde_derive;
extern crate time;
#[macro_use]
extern crate util;

use bft::BftActuator;
use clap::App;
use pubsub::channel;
use std::thread;
use cita_directories::DataPath;

mod core;
use crate::core::bft_bridge::{Processor, BftBridge};
use crate::core::params::{Config, PrivateKey};
use cpuprofiler::PROFILER;
use crate::crypto::Signer;
use libproto::router::{MsgType, RoutingKey, SubModules};
use pubsub::start_pubsub;
use std::thread::sleep;
use std::time::Duration;
use util::set_panic_handler;

fn profiler(flag_prof_start: u64, flag_prof_duration: u64) {
    //start profiling
    if flag_prof_duration != 0 {
        let start = flag_prof_start;
        let duration = flag_prof_duration;
        thread::spawn(move || {
            thread::sleep(std::time::Duration::new(start, 0));
            PROFILER
                .lock()
                .unwrap()
                .start("./tdmint.profiler")
                .expect("Couldn't start");
            thread::sleep(std::time::Duration::new(duration, 0));
            PROFILER.lock().unwrap().stop().unwrap();
        });
    }
}

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

fn main() {
    micro_service_init!("cita-bft", "CITA:consensus:cita-bft");
    info!("Version: {}", get_build_info_str(true));

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
        .get_matches();

    let mut config_path = "consensus.toml";
    if let Some(c) = matches.value_of("config") {
        trace!("Value for config: {}", c);
        config_path = c;
    }

    let mut pk_path = "privkey";
    if let Some(p) = matches.value_of("private") {
        trace!("Value for config: {}", p);
        pk_path = p;
    }

    let flag_prof_start = matches
        .value_of("prof-start")
        .unwrap_or("0")
        .parse::<u64>()
        .unwrap();
    let flag_prof_duration = matches
        .value_of("prof-duration")
        .unwrap_or("0")
        .parse::<u64>()
        .unwrap();

    // mq pubsub module
    let (r2p, p4r) = channel::unbounded();
    let (p2r, r4p) = channel::unbounded();
    start_pubsub(
        "consensus",
        routing_key!([
            Net >> CompactSignedProposal,
            Net >> RawBytes,
            Chain >> RichStatus,
            Auth >> BlockTxs,
            Auth >> VerifyBlockResp,
            Snapshot >> SnapshotReq,
        ]),
        r2p,
        r4p,
    );

    let config = Config::new(config_path);
    let pk = PrivateKey::new(pk_path);
    let signer = Signer::from(pk.signer);

    let main_thd = thread::spawn(move || {
        let (b2p, p4b) = channel::unbounded();
        let (p2b_b, b4p_b) = channel::unbounded();
        let (p2b_f, b4p_f) = channel::unbounded();
        let (p2b_s, b4p_s) = channel::unbounded();
        let (p2b_t, b4p_t) = channel::unbounded();

        let wal_path = DataPath::wal_path();

        let bridge = BftBridge::new(b2p, b4p_b, b4p_f, b4p_s, b4p_t);
        let bft_actuator = BftActuator::new(bridge, signer.address.to_vec(), &wal_path);
        let mut processor = Processor::new(p2b_b, p2b_f, p2b_s, p2b_t, p2r, p4b, p4r, bft_actuator, pk);
        processor.start();
    });

    // NTP service
    let ntp_config = config.ntp_config.clone();

    let mut log_tag: u8 = 0;

    if ntp_config.enabled {
        thread::spawn(move || loop {
            if ntp_config.is_clock_offset_overflow() {
                warn!("System clock seems off!!!");
                log_tag += 1;
                if log_tag == 10 {
                    log_tag = 0;
                    sleep(Duration::new(1000, 0));
                }
            } else {
                log_tag = 0;
            }

            sleep(Duration::new(10, 0));
        });
    }

    profiler(flag_prof_start, flag_prof_duration);

    main_thd.join().unwrap();
}



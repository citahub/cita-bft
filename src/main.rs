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

use clap::App;
use std::sync::mpsc::channel;
use std::thread;

mod core;
use core::cita_bft::{Bft, BftTurn};
use core::params::{BftParams, Config, PrivateKey};
use core::votetime::WaitTimer;
use cpuprofiler::PROFILER;
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

    // timer module
    let (main2timer, timer4main) = channel();
    let (sender, receiver) = channel();
    let timethd = {
        let sender = sender.clone();
        thread::spawn(move || {
            let wt = WaitTimer::new(sender, timer4main);
            wt.start();
        })
    };

    // mq pubsub module
    let (tx_sub, rx_sub) = channel();
    let (tx_pub, rx_pub) = channel();
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
        tx_sub,
        rx_pub,
    );
    thread::spawn(move || loop {
        let (key, body) = rx_sub.recv().unwrap();
        let tx = sender.clone();
        tx.send(BftTurn::Message((key, body))).unwrap();
    });

    let config = Config::new(config_path);

    let pk = PrivateKey::new(pk_path);

    // main cita-bft loop module
    let params = BftParams::new(&pk);
    let mainthd = thread::spawn(move || {
        let mut engine = Bft::new(tx_pub, main2timer, receiver, params);
        engine.start();
    });

    // NTP service
    let ntp_config = config.ntp_config.clone();
    // Default
    // let ntp_config = Ntp {
    //     enabled: true,
    //     threshold: 3000,
    //     address: String::from("0.pool.ntp.org:123"),
    // };
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

    mainthd.join().unwrap();
    timethd.join().unwrap();
}

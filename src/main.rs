// Copyright Rivtower Technologies LLC.
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

extern crate cita_crypto as crypto;
extern crate cita_types as types;
#[macro_use]
extern crate libproto;
#[macro_use]
extern crate cita_logger as logger;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate util;

use clap::App;
use pubsub::channel;
use std::env;
use std::thread;

mod core;
use crate::core::cita_bft::{Bft, BftTurn};
use crate::core::params::{BftParams, PrivateKey};
use crate::core::votetime::WaitTimer;
use crate::core::SignSymbol;
use crate::core::TimeOffset;
use cpuprofiler::PROFILER;
use libproto::router::{MsgType, RoutingKey, SubModules};
use pubsub::start_pubsub;
use std::cmp::Ordering;
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
    let matches = App::new("cita-bft")
        .version(get_build_info_str(true))
        .long_version(get_build_info_str(false))
        .author("Rivtower")
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
        .args_from_usage("--modify_time=[0], \
        'you can set a value to modify proposal time. eg. 10000: proposal time + 10s, -10000: proposal time -10s.'")
        .get_matches();

    let stdout = matches.is_present("stdout");
    micro_service_init!("cita-bft", "CITA:consensus:cita-bft", stdout);
    info!("Version: {}", get_build_info_str(true));

    let mut pk_path = "privkey";
    if let Some(p) = matches.value_of("private") {
        trace!("Value for private config: {}", p);
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
    let (main2timer, timer4main) = channel::unbounded();
    let (sender, receiver) = channel::unbounded();
    let timethd = {
        let sender = sender.clone();
        thread::spawn(move || {
            let wt = WaitTimer::new(sender, timer4main);
            wt.start();
        })
    };

    // mq pubsub module
    let (tx_sub, rx_sub) = channel::unbounded();
    let (tx_pub, rx_pub) = channel::unbounded();
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

    let pk = PrivateKey::new(pk_path);

    // main cita-bft loop module
    let params = BftParams::new(&pk);
    let mainthd = thread::spawn(move || {
        let mut engine = Bft::new(tx_pub, main2timer, receiver, params);
        let mut time_offset: i64 = 0;
        if matches.is_present("modify_time") || env::var("MODIFY_TIME").is_ok() {
            if let Some(time) = matches.value_of("modify_time") {
                time_offset = time.parse().unwrap_or_else(|err| {
                    warn!("time modify: cli {} parse to i64 error: {}", time, err);
                    0
                });
            }

            if time_offset == 0 {
                if let Ok(time) = env::var("MODIFY_TIME") {
                    time_offset = time.parse().unwrap_or_else(|err| {
                        warn!("time modify: env {} parse to i64 error: {}", time, err);
                        0
                    });
                }
            }

            match time_offset.cmp(&0) {
                Ordering::Greater => {
                    engine.mock_time_modify =
                        TimeOffset::new(SignSymbol::Positive, time_offset as u64);
                }
                Ordering::Equal => {
                    engine.mock_time_modify = TimeOffset::new(SignSymbol::Zero, 0);
                }
                Ordering::Less => {
                    engine.mock_time_modify =
                        TimeOffset::new(SignSymbol::Negative, (-time_offset) as u64);
                }
            }

            info!(
                "Use timestamp modify function, the param: {:?}",
                engine.mock_time_modify
            )
        }
        engine.start();
    });

    profiler(flag_prof_start, flag_prof_duration);

    mainthd.join().unwrap();
    timethd.join().unwrap();
}

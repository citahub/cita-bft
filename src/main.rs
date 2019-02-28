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
#![feature(try_from)]
extern crate authority_manage;
extern crate bft_rs;
extern crate bincode;
extern crate cita_crypto as crypto;
extern crate cita_types as types;
extern crate clap;
extern crate crossbeam;
extern crate dotenv;
extern crate engine;
#[macro_use]
extern crate libproto;
#[macro_use]
extern crate logger;
extern crate lru_cache;
extern crate proof;
extern crate pubsub;
extern crate rustc_hex;
extern crate time;
#[macro_use]
extern crate util;

use bft_rs::algorithm::Bft as AlgoBft;
use clap::App;
mod core;
use core::cita_bft::{Bft, MixMsg};
use crossbeam::crossbeam_channel::unbounded;
use crypto::{PrivKey, Signer};
use libproto::router::{MsgType, RoutingKey, SubModules};
use pubsub::start_pubsub;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::thread;
use types::clean_0x;
use util::set_panic_handler;

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

    let mut pk_path = "privkey";
    if let Some(p) = matches.value_of("private") {
        trace!("Value for config: {}", p);
        pk_path = p;
    }

    let mut buffer = String::new();
    File::open(pk_path)
        .and_then(|mut f| f.read_to_string(&mut buffer))
        .unwrap_or_else(|err| panic!("Error while loading PrivateKey: [{}]", err));

    let signer = PrivKey::from_str(clean_0x(&buffer)).unwrap();
    let bft_signer = signer.clone();

    let signer = Signer::from(signer);
    let bft_signer = Signer::from(bft_signer);

    let address: &[u8] = bft_signer.address.as_ref();
    let address = Vec::from(address);

    let (rab2cita, cita4rab) = channel();
    let (cita2rab, rab4cita) = channel();

    let (bft2cita, cita4bft) = unbounded();
    let (cita2bft, bft4cita) = unbounded();

    let (sender, receiver) = unbounded();

    start_pubsub(
        "consensus",
        routing_key!([
            Net >> SignedProposal,
            Net >> RawBytes,
            Chain >> RichStatus,
            Auth >> BlockTxs,
            Auth >> VerifyBlockResp,
        ]),
        rab2cita,
        rab4cita,
    );

    let rab_sender = sender.clone();

    thread::spawn(move || {
        let (key, body) = cita4rab.recv().unwrap();
        rab_sender.send(MixMsg::RabMsg((key, body))).unwrap();
    });


    let bft_thread = {
        thread::spawn(move || {
            AlgoBft::start(bft2cita, bft4cita, address);
        })
    };

    thread::spawn(move || {
        let msg = cita4bft.recv().unwrap();
        let sender = sender.clone();
        sender.send(MixMsg::BftMsg(msg)).unwrap();
    });

    let main_thread = thread::spawn(move || {
        let mut engine = Bft::new(cita2rab, cita2bft, receiver, signer);
        let _ = engine.start();
    });

    bft_thread.join().unwrap();
    main_thread.join().unwrap();
}
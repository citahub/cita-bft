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

#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![feature(custom_attribute)]
#![allow(unused_must_use)]
#![feature(mpsc_select)]
#![feature(try_from)]

extern crate authority_manage;
extern crate bincode;
extern crate cita_crypto as crypto;
extern crate clap;
extern crate cpuprofiler;
extern crate dotenv;
extern crate engine;
#[macro_use]
extern crate libproto;
#[macro_use]
extern crate log;
extern crate logger;
extern crate lru_cache;
extern crate ntp;
extern crate proof;
extern crate protobuf;
extern crate pubsub;
extern crate rustc_hex;
#[macro_use]
extern crate serde_derive;
extern crate threadpool;
extern crate time;
#[macro_use]
extern crate util;

use clap::App;
use std::sync::mpsc::channel;
use std::thread;

mod core;
use core::cita_bft::TenderMint;
use core::ntp::Ntp;
use core::params::TendermintParams;
use core::votetime::WaitTimer;
use cpuprofiler::PROFILER;
use libproto::router::{MsgType, RoutingKey, SubModules};
use pubsub::start_pubsub;
use std::thread::sleep;
use std::time::Duration;
use util::set_panic_handler;

const THREAD_POOL_NUM: usize = 10;

fn profiler(flag_prof_start: u64, flag_prof_duration: u64) {
    //start profiling
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

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

fn main() {
    micro_service_init!("cita-bft", "CITA:consensus:cita-bft");

    let matches = App::new("cita-bft")
        .version(get_build_info_str(true))
        .long_version(get_build_info_str(false))
        .author("Cryptape")
        .about("CITA Block Chain Node powered by Rust")
        .args_from_usage("-c, --config=[FILE] 'Sets a custom config file'")
        .args_from_usage("-n, --ntp=[FILE] 'Sets a ntp config file'")
        .args_from_usage("--prof-start=[0] 'Specify the start time of profiling, zero means no profiling'")
        .args_from_usage("--prof-duration=[0] 'Specify the duration for profiling, zero means no profiling'")
        .get_matches();

    let mut config_path = "config";
    if let Some(c) = matches.value_of("config") {
        trace!("Value for config: {}", c);
        config_path = c;
    }

    let mut ntp_path = "ntp";
    if let Some(ntp) = matches.value_of("ntp") {
        trace!("Value for ntp: {}", ntp);
        ntp_path = ntp;
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

    profiler(flag_prof_start, flag_prof_duration);
    // timer module
    let (main2timer, timer4main) = channel();
    let (timer2main, main4timer) = channel();
    let timethd = thread::spawn(move || {
        let wt = WaitTimer::new(timer2main, timer4main);
        wt.start();
    });

    // mq pubsub module
    let threadpool = threadpool::ThreadPool::new(THREAD_POOL_NUM);
    let (mq2main, main4mq) = channel();
    let (tx_sub, rx_sub) = channel();
    let (tx_pub, rx_pub) = channel();
    start_pubsub(
        "consensus",
        routing_key!([
            Net >> SignedProposal,
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
        let tx = mq2main.clone();
        let pool = threadpool.clone();
        pool.execute(move || {
            tx.send((key, body)).unwrap();
        });
    });

    // main cita-bft loop module
    let params = TendermintParams::new(config_path);
    info!("main loop start **** ");
    let mainthd = thread::spawn(move || {
        let mut engine = TenderMint::new(tx_pub, main4mq, main2timer, main4timer, params);
        engine.start();
    });

    // NTP service
    let ntp_config = Ntp::new(ntp_path);
    // Default
    // let ntp_config = Ntp {
    //     enabled: true,
    //     threshold: 3000,
    //     address: String::from("0.pool.ntp.org:123"),
    // };
    let mut log_tag: u8 = 0;

    if ntp_config.switch == true {
        thread::spawn(move || loop {
            if ntp_config.clock_offset_overflow() {
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

    mainthd.join().unwrap();
    timethd.join().unwrap();
}

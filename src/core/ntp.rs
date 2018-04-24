// CITA
// Copyright 2016-2018 Cryptape Technologies LLC.

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
//
//! > To calculate the roundtrip delay d and system clock offset t relative
//! > to the server, the client sets the Transmit Timestamp field in the
//! > request to the time of day according to the client clock in NTP
//! > timestamp format.  For this purpose, the clock need not be
//! > synchronized.  The server copies this field to the Originate
//! > Timestamp in the reply and sets the Receive Timestamp and Transmit
//! > Timestamp fields to the time of day according to the server clock in
//! > NTP timestamp format.
//! >
//! > When the server reply is received, the client determines a
//! > Destination Timestamp variable as the time of arrival according to
//! > its clock in NTP timestamp format.  The following table summarizes
//! > the four timestamps.
//! >
//! >    Timestamp Name          ID   When Generated
//! >    ------------------------------------------------------------
//! >    Originate Timestamp     T1   time request sent by client
//! >    Receive Timestamp       T2   time request received by server
//! >    Transmit Timestamp      T3   time reply sent by server
//! >    Destination Timestamp   T4   time reply received by client
//! >
//! > The roundtrip delay d and system clock offset t are defined as:
//! >
//! > d = (T4 - T1) - (T3 - T2)     t = ((T2 - T1) + (T3 - T4)) / 2.
//!
//! More details at [SNTP](https://tools.ietf.org/html/rfc4330).

use ntp::errors::Error;
use ntp::request;
use time::{Duration, Timespec};
use time::now_utc;

#[derive(Debug, Deserialize)]
pub struct Ntp {
    pub enabled: bool,
    pub threshold: i64,
    pub address: String,
}

impl Ntp {
    /// New a config form the path
    pub fn new(path: &str) -> Self {
        let config = parse_config!(Ntp, path);
        config.into()
    }

    /// Check the system clock offset overflow the threshold
    pub fn clock_offset_overflow(&self) -> bool {
        let mut offset_overflow = false;

        match Ntp::system_clock_offset(self) {
            Ok(offset) => {
                if offset.num_milliseconds().abs() > self.threshold {
                    debug!("System clock seems off by {}", offset);
                    offset_overflow = true;
                }
                offset_overflow
            }
            Err(_) => true,
        }
    }

    /// Caclulate the system clock offset relative to the ntp server
    fn system_clock_offset(&self) -> Result<Duration, Error> {
        match request(self.address.clone()) {
            Ok(packet) => {
                let dest = now_utc().to_timespec();
                let orig = Timespec::from(packet.orig_time);
                let recv = Timespec::from(packet.recv_time);
                let transmit = Timespec::from(packet.transmit_time);

                let offset = ((recv - orig) + (transmit - dest)) / 2;

                Ok(offset)
            }
            Err(err) => {
                debug!("Fetch time err: {}", err);
                Err(err)
            }
        }
    }
}

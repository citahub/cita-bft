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

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs::{read_dir, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::mem::transmute;
use std::str;

const DELETE_FILE_INTERVAL: usize = 3;

#[derive(Debug, Clone, Copy)]
pub enum LogType {
    Skip = !0,
    Propose = 1,
    Vote = 2,
    State = 3,
    PrevHash = 4,
    Commits = 5,
    VerifiedPropose = 6,
    VerifiedBlock = 8,
    AuthTxs = 9,
}

impl From<u8> for LogType {
    fn from(s: u8) -> LogType {
        match s {
            1 => LogType::Propose,
            2 => LogType::Vote,
            3 => LogType::State,
            4 => LogType::PrevHash,
            5 => LogType::Commits,
            6 => LogType::VerifiedPropose,
            8 => LogType::VerifiedBlock,
            9 => LogType::AuthTxs,
            _ => LogType::Skip,
        }
    }
}

pub struct Wal {
    height_fs: BTreeMap<usize, File>,
    dir: String,
    current_height: usize,
    ifile: File,
}

impl Wal {
    pub fn create(dir: &str) -> Result<Wal, io::Error> {
        let fss = read_dir(&dir);
        if fss.is_err() {
            DirBuilder::new().recursive(true).create(dir).unwrap();
        }

        let file_path = dir.to_string() + "/" + "index";
        let mut ifs = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .open(file_path)?;
        ifs.seek(io::SeekFrom::Start(0)).unwrap();

        let mut string_buf: String = String::new();
        let res_fsize = ifs.read_to_string(&mut string_buf)?;
        let cur_height: usize;
        let last_file_path: String;
        if res_fsize == 0 {
            last_file_path = dir.to_string() + "/1.log";
            cur_height = 1;
        } else {
            let hi_res = string_buf.parse::<usize>();
            if let Ok(hi) = hi_res {
                cur_height = hi;
                last_file_path = dir.to_string() + "/" + cur_height.to_string().as_str() + ".log"
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "index file data wrong",
                ));
            }
        }

        let fs = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .open(last_file_path)?;

        let mut tmp = BTreeMap::new();
        tmp.insert(cur_height, fs);

        Ok(Wal {
            height_fs: tmp,
            dir: dir.to_string(),
            current_height: cur_height,
            ifile: ifs,
        })
    }

    fn get_file_path(dir: &str, height: usize) -> String {
        let mut name = height.to_string();
        name += ".log";
        let pathname = dir.to_string() + "/";
        pathname + &*name
    }

    pub fn set_height(&mut self, height: usize) -> Result<(), io::Error> {
        self.current_height = height;
        self.ifile.seek(io::SeekFrom::Start(0))?;
        let hstr = height.to_string();
        let content = hstr.as_bytes();
        let _ = self.ifile.set_len(content.len() as u64);
        self.ifile.write_all(&content)?;
        self.ifile.sync_data()?;

        let filename = Wal::get_file_path(&self.dir, height);
        let fs = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(filename)?;
        self.height_fs.insert(height, fs);

        if height > DELETE_FILE_INTERVAL {
            self.height_fs.remove(&(height - DELETE_FILE_INTERVAL));
            let delfilename = Wal::get_file_path(&self.dir, height - DELETE_FILE_INTERVAL);
            let _ = ::std::fs::remove_file(delfilename);
        }
        Ok(())
    }

    pub fn save(&mut self, height: usize, log_type: LogType, msg: &[u8]) -> io::Result<usize> {
        let mtype = log_type as u8;
        if !self.height_fs.contains_key(&height) {
            // 2 more higher then current height, not process it
            match height.partial_cmp(&(self.current_height + 1)) {
                Some(Ordering::Equal) => {
                    let filename = Wal::get_file_path(&self.dir, height);
                    let fs = OpenOptions::new()
                        .read(true)
                        .create(true)
                        .write(true)
                        .open(filename)?;
                    self.height_fs.insert(height, fs);
                }
                Some(Ordering::Greater) => {
                    return Ok(0);
                }
                _ => {}
            }
        }
        let mlen = msg.len() as u32;
        if mlen == 0 {
            return Ok(0);
        }

        let mut hlen = 0;
        if let Some(fs) = self.height_fs.get_mut(&height) {
            let len_bytes: [u8; 4] = unsafe { transmute(mlen.to_le()) };
            let type_bytes: [u8; 1] = unsafe { transmute(mtype.to_le()) };
            fs.seek(io::SeekFrom::End(0))?;
            fs.write_all(&len_bytes[..])?;
            fs.write_all(&type_bytes[..])?;
            hlen = fs.write(msg)?;
            fs.flush()?;
        } else {
            warn!("cita-bft wal save error height {} ", height);
        }
        Ok(hlen)
    }

    pub fn load(&mut self) -> Vec<(u8, Vec<u8>)> {
        let mut vec_buf: Vec<u8> = Vec::new();
        let mut vec_out: Vec<(u8, Vec<u8>)> = Vec::new();
        let cur_height = self.current_height;
        if self.height_fs.is_empty() || cur_height == 0 {
            return vec_out;
        }

        for (height, mut fs) in &self.height_fs {
            if *height < self.current_height {
                continue;
            }
            fs.seek(io::SeekFrom::Start(0)).unwrap();
            let res_fsize = fs.read_to_end(&mut vec_buf);
            if res_fsize.is_err() {
                return vec_out;
            }
            let fsize = res_fsize.unwrap();
            if fsize <= 5 {
                return vec_out;
            }
            let mut index = 0;
            loop {
                if index + 5 > fsize {
                    break;
                }
                let hd: [u8; 4] = [
                    vec_buf[index],
                    vec_buf[index + 1],
                    vec_buf[index + 2],
                    vec_buf[index + 3],
                ];
                let tmp: u32 = unsafe { transmute::<[u8; 4], u32>(hd) };
                let bodylen = tmp as usize;
                let mtype = vec_buf[index + 4];
                index += 5;
                if index + bodylen > fsize {
                    break;
                }
                vec_out.push((mtype, vec_buf[index..index + bodylen].to_vec()));
                index += bodylen;
            }
        }
        vec_out
    }
}

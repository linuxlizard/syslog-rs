// A syslog server tuned for Cradlepoint routers which have several options for
// sysylog features. Listen for syslog messages from multiple differently
// configured routers. Must parse the message to find the different fields the
// router might send.
//
//
// davep 20250328

use std::net::UdpSocket;
//use regex::Regex;
// https://docs.rs/chrono/0.4.42/chrono/index.html
use chrono::prelude::*;
use chrono::format::{ ParseError };
use clap::Parser;

/// A syslog server tuned for Cradlepoint routers
#[derive(Parser, Debug, Clone, PartialEq)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Enable debug mode
    #[arg(long)]
    pub debug: bool,

    /// UDP port to listen on
    #[arg(long, default_value_t = 5514)]
    pub port: u16,
}

const TIMESTAMP_WITH_TZ:&str = "%Y%m%dT%H%M%S%z";
const TIMESTAMP_WITHOUT_TZ:&str = "%Y%m%dT%H%M%S";

// https://www.rfc-editor.org/rfc/rfc3164
// https://www.rfc-editor.org/rfc/rfc5424

fn get_contents(buf: &[u8]) -> String {
    // make the best effort to extract a human-readable string from the message

    // first look for possible RFC-5424 BOM
    // https://en.wikipedia.org/wiki/Byte_order_mark
    // ef bb bf indicates UTF-8
    let payload = buf.strip_prefix(b"\xef\xbb\xbf").unwrap_or(buf);
    String::from_utf8_lossy(payload).into_owned()
}

fn parse_timestamp(s:&str) -> Result<DateTime<FixedOffset>, ParseError> {
    // e.g. 20251019T070037-0600

    // with lots of help from Rust Rover (Claude 4.5)
    let dt: Result<DateTime<FixedOffset>, ParseError> = if s.contains('-') {
        DateTime::parse_from_str(s, TIMESTAMP_WITH_TZ)
            .inspect_err(|e| println!("Error parsing date: {}", e))
    } else {
        /*  FIXME! 
         *
         *  do NOT blindly add UTC TZ to timestamp without TZ.
         *  Add a way to know TZ vs no-TZ timestamp.
         *
         */
        NaiveDateTime::parse_from_str(s, TIMESTAMP_WITHOUT_TZ)
            .map(|naive| naive.and_utc().fixed_offset())
            .inspect_err(|e| println!("Error parsing naive date: {}", e))
    };

    dt
}

#[derive(Debug, Clone, PartialEq)]
struct Syslog {
    facility: u8,
    severity: u8,
    timestamp: Option<DateTime<FixedOffset>>,
    hostname: Option<String>,
    appname: Option<String>,
    message: String
}

impl std::fmt::Display for Syslog
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // timestamp has whitespace so surround with()
        write!(f, "({}) {} {} {} {} {}",  
                self.timestamp
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(||"??".to_string()),
                self.facility,
                self.severity,
                self.hostname.as_deref().unwrap_or("??"),
                self.appname.as_deref().unwrap_or("??"),
                self.message)
    }
}

fn parse_syslog_message(buf: &[u8] ) -> Option<Syslog> {
    let mut idx = 0;

    // must start with '<' == 0x3c
    if !buf.starts_with(b"<") {
        return None;
    }

    idx += 1;

    // look for end of priority '>' == 0x3e
    while buf[idx] != 0x3e {
        idx += 1;

        if idx >= buf.len() {
            // ran out of buffer
            return None;
        }

        // should only be a small number
        if idx > 6 {
            // TODO report why failed
            return None;
        }
    }

    let pri:u8 = std::str::from_utf8(&buf[1..idx])
        .ok()?
        .parse()
        .ok()?;

    let facility = pri / 8;
    let severity = pri % 8;

    idx += 1;

    let contents = get_contents(&buf[idx..]);

    // from this point on, we get to parse a String!  Yay!
    let timestamp: Option<DateTime<FixedOffset>> = None;
    let hostname: Option<String> = None;
    let appname: Option<String> = None;
    let _message: Option<String> = None;

    // timestamp is optional; look for next whitespace then test string for timestamp-ish-ness
    // RFC-3164 has timestamp + hostname

    let pos = contents.find(' ');

    if pos.is_none() {
        // no whitespace!? just return what we have
        return Some(Syslog {
                        facility,
                        severity,
                        timestamp,
                        hostname,
                        appname,
                        message:contents
                    });
    }

    let pos:usize = pos.unwrap();
    let timestamp = 
        match parse_timestamp(&contents[..pos]) {
            Ok(ts) => {
//                println!("ts={:?}", ts);
//                println!("offset={}", ts.timezone());
//                println!("Time: {}:{}:{}", ts.hour(), ts.minute(), ts.second());
//                println!("Date: {}{}{} {}", ts.year(), ts.month(), ts.day(), ts.timezone());
                Some(ts)
            },
            Err(_) => None
       };

    // find the hostname
    let next = contents[pos+1..].find(' ');
    if next.is_none() {
        return Some(Syslog {
                    facility,
                    severity,
                    timestamp,
                    hostname,
                    appname,
                    message: contents[pos..].to_string()
                  });
    }

    let next:usize = pos +1 + next.unwrap();
    let hostname = Some(contents[pos+1..next].to_string());

    let pos:usize = next+1;

    // find the appname
    let next = contents[pos..].find(' ');
    if next.is_none() {
        return Some(Syslog {
                    facility,
                    severity,
                    timestamp,
                    hostname,
                    appname,
                    message: contents[pos..].to_string()
                  });
    }

    let next:usize = pos + next.unwrap();
//    println!("pos={} next={}", pos, next);
    let appname = Some(contents[pos..next].to_string());

    let pos:usize = next+1;

    Some( Syslog {
                    facility,
                    severity,
                    timestamp,
                    hostname,
                    appname,
                    message:contents[pos..].to_string()
                } )
}


fn hex_dump(buf: &[u8]) {

    let _str1: Vec<char> = Vec::new();

    for (i,chunk) in buf.chunks(16).enumerate() {
        let offset = i * 16;

        // build hex part
        let mut hex_part = String::with_capacity(48);
        for byte in chunk {
            use std::fmt::Write;
            let _ = write!(hex_part, "{:02X} ", byte);
        }

        // build ascii part
        let ascii_part: String = chunk
            .iter()
            .map(|x| if *x >= 0x20 && *x <= 0x7e  {*x as char} else {'.'})
            .collect();

        println!("{offset:#010X} {hex_part:48} {ascii_part}");

    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let socket = UdpSocket::bind(("0.0.0.0", args.port))?;
    println!("Listening for syslog messages on port {}...", args.port);
    
    let now: DateTime<Local> = Local::now();
    println!("now={}", now);

    let mut buf = [0u8; 1024];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, _src)) => {
                if args.debug {
                    hex_dump(&buf[..size]);
                }

                if let Some(logmsg) = parse_syslog_message(&buf[..size]) {
                    print!("{}\n", logmsg);
                } else {
                    println!("  Failed to parse syslog message.");
                }
            }
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
            }
        }
        // just do one message (for testing)
//        break;
    }

}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_timestamp() {
        let s = "20251024T184520-0600";
        let x = parse_timestamp(&s);
        assert!(x.is_ok());
        _ = x.and_then(|ts| { println!("ts={:?}",ts); Ok(()) } );

        // experimenting
        let x = DateTime::parse_from_str(s, TIMESTAMP_WITHOUT_TZ)
            .inspect_err(|e| println!("error1={}", e));
        assert!(x.is_err());

        let x = DateTime::parse_from_str(s, TIMESTAMP_WITH_TZ)
            .inspect_err(|e| println!("error2={}", e));
        assert!(x.is_ok());

        let s = "20251024T200456-0600 (IBR1700-f11) gps.src.gnssd.firehose: connect";
        match DateTime::parse_and_remainder(s, TIMESTAMP_WITH_TZ) {
            Ok((ts, remainder)) => {
                println!("ts={} remainder={}", ts, remainder);
            },
            Err(e) => {
                println!("error3={}", e);
            }
        }

        let s = "qqqq1024T200456-0600 (IBR1700-f11)";
        match DateTime::parse_and_remainder(s, TIMESTAMP_WITH_TZ) {
            Ok((thex, remainder)) => {
                println!("remainder={}",remainder);
            },
            Err(e) => {
                println!("error4={}", e);
            }
        }

    }

    #[test]
    fn test_parse_timestamp_no_timezone() {
        let s = "20251024T184520";
        let x = parse_timestamp(&s);
        assert!(x.is_ok());
        if let Ok(ts) = x {
            println!("no tz ts={:?}",ts);
        }

        let ts = NaiveDateTime::parse_from_str(&s, TIMESTAMP_WITH_TZ);
        assert!(ts.is_err());
    }

}



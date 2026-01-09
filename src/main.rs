// A syslog server tuned for Cradlepoint routers which have several options for
// sysylog features. Listen for syslog messages from multiple differently
// configured routers. Must parse the message to find the different fields the
// router might send.
//
//
// davep 20250328

use std::net::UdpSocket;
//use regex::Regex;
use chrono::prelude::*;
use chrono::format::{ ParseError };

const TIMESTAMP_WITH_TZ:&str = "%Y%m%dT%H%M%S%z";
const TIMESTAMP_WITHOUT_TZ:&str = "%Y%m%dT%H%M%S";

// https://www.rfc-editor.org/rfc/rfc3164
// https://www.rfc-editor.org/rfc/rfc5424

fn get_contents(buf: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    // make best effort to extract a human readable string from the message

    // first look for possible RFC-5424 BOM
    // https://en.wikipedia.org/wiki/Byte_order_mark
    // ef bb bf indicates UTF-8
    let contents = if buf[0] == 0xef && buf[1] == 0xbb && buf[2] == 0xbf 
    {
        // expect a valid UTF8 string (this is probably a mistake (waves to
        // Future Dave))
        String::from_utf8(buf[3..].to_vec())?
    }
    else {
        // hope for the best
        String::from_utf8_lossy(&buf.to_vec()).to_string()
    };

    Ok(contents)
}

fn parse_timestamp(s:&str) -> Result<DateTime<FixedOffset>, ParseError> {
    // e.g. 20251019T070037-0600

    println!("parse_timestamp s={}", s);
    // with lots of help from Rust Rover (Claude 4.5)
    let dt: Result<DateTime<FixedOffset>, ParseError> = if s.contains('-') {
        DateTime::parse_from_str(s, TIMESTAMP_WITH_TZ)
            .inspect_err(|e| println!("Error parsing date: {}", e))
    } else {
        NaiveDateTime::parse_from_str(s, TIMESTAMP_WITHOUT_TZ)
            .map(|naive| naive.and_utc().fixed_offset())
            .inspect_err(|e| println!("Error parsing naive date: {}", e))
    };

    dt
}

struct Syslog {
    facility: u8,
    severity: u8,
    timestamp: Option<DateTime<FixedOffset>>,
    hostname: Option<String>,
    appname: Option<String>,
    message: String
}

fn parse_syslog_message(buf: &[u8] ) -> Option<Syslog> {
    
    let mut idx = 0;

    // must start with '<' == 0x3c
    if buf[idx] != 0x3c {
        // TODO report why failed
        return None
    }

    idx += 1;

    // look for end of priority '>' == 0x3e
    while buf[idx] != 0x3e {
        idx += 1;

        // should only be a small number
        if idx > 6 {
            // TODO report why failed
            return None;
        }
    }

    let pri:u8 = std::str::from_utf8(&buf[1..idx]).ok()?.parse().ok()?;
    println!("pri={}",pri);
    
    let facility = pri / 8;
    let severity = pri % 8;

    idx += 1;

    let contents = match get_contents(&buf[idx..]) {
        Ok(s) => s,
        Err(e) => {
            let err = e.utf8_error();
            eprintln!("utf8 decode error; valid up to {}", err.valid_up_to());
            return None
        }
    };
    // from this point on, we get to parse a String!  Yay!
    println!("contents={}",contents);

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
                println!("ts={:?}", ts);
                println!("offset={}", ts.timezone());
                println!("Time: {}:{}:{}", ts.hour(), ts.minute(), ts.second());
                println!("Date: {}{}{} {}", ts.year(), ts.month(), ts.day(), ts.timezone());
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
    println!("pos={} next={}", pos, next);
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
    let mut counter = 0;
    for chunk in buf.chunks(16) {
        let s1 = chunk
            .iter()
            .map(|x| format!("{:02X}", x))
            .collect::<Vec<String>>()
            .join(" ");

        let s2 = chunk
            .iter()
            .map(|x| if *x >= 0x20 && *x <= 0x73  {*x as char} else {'.'})
            .collect::<String>();

        println!("{:#010X} {:48} {}", counter, s1, s2);
        counter += chunk.len();
    }
}

fn _old_hex_dump( buf: &[u8] ) {
    let mut counter = 0;
    let mut s = String::new();

    for b in buf {
        print!("{:02x} ", b);

        if *b >= 0x20 && *b <= 0x7e {
            s.push(*b as char);
        }
        else {
            s.push('.');
        }

        counter += 1;
        if counter==16 {
            println!(" {}", s);
            s.clear();
            counter = 0;
        }
    }
    if counter != 0 {
        let whitespace:String = "   ".repeat(16-counter);
        println!("{} {}", whitespace, s);
    }

}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:5514")?;
    println!("Listening for syslog messages on port 5514...");
    
    let now: DateTime<Local> = Local::now();
    println!("now={}", now);

    let mut buf = [0u8; 1024];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, _src)) => {
                hex_dump(&buf[..size]);

//                let raw_message = String::from_utf8_lossy(&buf[..size]);
//                println!("Received from {}: {}", src, raw_message);
//                print!("{}", raw_message);

                if let Some(logmsg) = parse_syslog_message(&buf[..size]) {
                    println!("Parsed Syslog Message:");
                    println!("  Facility: {}", logmsg.facility);
                    println!("  Severity: {}", logmsg.severity);
                    println!("  Timestamp: {:?}", logmsg.timestamp);
                    println!("  Hostname: {:?}", logmsg.hostname);
                    println!("  App Name: {:?}", logmsg.appname);
                    println!("  Message: {:?}", logmsg.message);
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
    Ok(())
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
            Ok((x, remainder)) => {
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



extern crate chrono;
extern crate eui48;
extern crate fnv;

use chrono::{DateTime, TimeZone};
use chrono::prelude::Local;

use fnv::FnvHashMap;

use std::borrow::Cow;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

type OuiToOrganization = FnvHashMap<String, String>;

fn read_oui_file() -> Result<OuiToOrganization, std::io::Error> {
  let file = File::open("/usr/local/etc/oui.txt")?;

  let buf_reader = BufReader::new(&file);

  let mut oui_to_organization = OuiToOrganization::default();

  for line in buf_reader.lines() {
    let line_string = line?;

    let line_string = line_string.trim();

    if line_string.is_empty() {
      continue;
    }

    if let Some(i) = line_string.find(char::is_whitespace) {
      if i == 0 {
        continue;
      }
    }

    let split: Vec<&str> = line_string.split_whitespace().collect();

    if (split.len() >= 3) && (split[1] == "(hex)") {
      let mut org = String::new();
      for i in 2..split.len() {
        org.push_str(split[i]);
        org.push(' ');
      }
      oui_to_organization.insert(split[0].to_string().to_uppercase(), org);
    }
  }

  Ok(oui_to_organization)
}

#[derive(Debug)]
struct DhcpdLease {
  ip: String,
  start: Option<DateTime<Local>>,
  end: Option<DateTime<Local>>,
  mac: Option<eui48::MacAddress>,
  hostname: Option<String>
}

impl DhcpdLease {

  fn new(ip: String) -> Self {
    return DhcpdLease {
      ip,
      start: None,
      end: None,
      mac: None,
      hostname: None
    }
  }

  fn is_after(&self, other_option: Option<&DhcpdLease>) -> bool {
    match other_option {
      Some(other) => { 
        self.end.unwrap_or_else(|| Local.timestamp(0, 0)) >= 
          other.end.unwrap_or_else(|| Local.timestamp(0, 0))
      },
      None => true
    }
  }

}

type IPToDhcpdLease = FnvHashMap<String, DhcpdLease>;

fn read_dhcpd_leases() -> Result<IPToDhcpdLease, Box<std::error::Error>> {
  let file = File::open("/var/lib/dhcp/dhcpd.leases")?;

  let buf_reader = BufReader::new(&file);

  let mut current_lease_option: Option<DhcpdLease> = None;

  let mut ip_to_dhcpd_lease = IPToDhcpdLease::default();

  for line in buf_reader.lines() {
    let line_string = line?;

    let line_string = line_string.trim();

    if line_string.is_empty() {
      continue;
    }

    if line_string.starts_with('#') {
      continue;
    }

    let split: Vec<&str> = line_string.split_whitespace().collect();

    if current_lease_option.is_none() {
      if (split.len() >= 2) && (split[0] == "lease") && (split[2] == "{") {
        current_lease_option = Some(DhcpdLease::new(split[1].to_string()));
      }
    } 

    else {

      if split[0] == "}" {
        if let Some(current_lease) = current_lease_option {
          if current_lease.is_after(ip_to_dhcpd_lease.get(&current_lease.ip)) {
            ip_to_dhcpd_lease.insert(current_lease.ip.clone(), current_lease);
          }
        }
        current_lease_option = None;
      }

      else if (split.len() >= 4) && (split[0] == "starts") {
        if let Some(current_lease) = current_lease_option.as_mut() {
          let mut time = String::new();
          time.push_str(&split[2].replace("/", "-"));
          time.push('T');
          time.push_str(split[3].trim_matches(';'));
          time.push_str("+00:00");

          let utc_datetime = DateTime::parse_from_rfc3339(&time)?;

          let local_datetime = utc_datetime.with_timezone(&Local);

          current_lease.start = Some(local_datetime);
        }
      }

      else if (split.len() >= 4) && (split[0] == "ends") {
        if let Some(current_lease) = current_lease_option.as_mut() {
          let mut time = String::new();
          time.push_str(&split[2].replace("/", "-"));
          time.push('T');
          time.push_str(split[3].trim_matches(';'));
          time.push_str("+00:00");

          let utc_datetime = DateTime::parse_from_rfc3339(&time)?;

          let local_datetime = utc_datetime.with_timezone(&Local);

          current_lease.end = Some(local_datetime);
        }
      }

      else if (split.len() >= 3) && (split[0] == "hardware") && (split[1] == "ethernet") {
        if let Some(current_lease) = current_lease_option.as_mut() {
          let mac_address = eui48::MacAddress::parse_str(split[2].trim_matches(';'))?;
          current_lease.mac = Some(mac_address);
        }
      }

      else if (split.len() >= 2) && (split[0] == "client-hostname") {
        if let Some(current_lease) = current_lease_option.as_mut() {
          let hostname = split[1].trim_matches('"').to_string();
          let hostname = hostname.trim_matches(';').to_string();
          let hostname = hostname.trim_matches('"').to_string();
          current_lease.hostname = Some(hostname);
        }
      }
    }
  }

  Ok(ip_to_dhcpd_lease)
}

fn main() {
  let oui_to_organization = match read_oui_file() {
    Ok(o) => o,
    Err(e) => {
      println!("error reading oui file {}", e);
      OuiToOrganization::default()
    }
  };

  let ip_to_dhcpd_lease = read_dhcpd_leases().expect("error reading dhcpd.leases");

  println!("{:18}{:28}{:20}{:24}{}", "IP", "End Time", "MAC", "Hostname", "Organization");
  println!("====================================================================================================================");

  let mut ips: Vec<_> = ip_to_dhcpd_lease.keys().collect();
  ips.sort();

  for ip in ips {
    let lease = ip_to_dhcpd_lease.get(ip).unwrap();

    let end = match lease.end {
      Some(end) => end.to_string(),
      None => "NA".to_string()
    };

    let mac = match lease.mac {
      Some(mac) => mac.to_hex_string(),
      None => "NA".to_string()
    };

    let hostname = match lease.hostname {
      Some(ref hostname) => hostname.clone(),
      None => "NA".to_string()
    };

    let oui = match lease.mac {
      Some(mac) => {
        mac.to_canonical()[..8].to_string().to_uppercase()
      },
      None => "".to_string()
    };

    let organization = match oui_to_organization.get(&oui) {
      Some(organization) => Cow::from(organization.clone()),
      None => Cow::from("NA")
    };
    println!("{:18}{:28}{:20}{:24}{}", ip, end, mac, hostname, organization);
  }
}

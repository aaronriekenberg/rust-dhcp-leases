extern crate chrono;
extern crate eui48;
extern crate fnv;
extern crate regex;

use chrono::{DateTime, TimeZone};
use chrono::prelude::Local;

use fnv::FnvHashMap;
use fnv::FnvHashSet;

use regex::Regex;

use std::borrow::Cow;
use std::default::Default;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

type OuiToOrganization = FnvHashMap<String, String>;

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

type OuiSet = FnvHashSet<String>;

fn mac_to_oui(mac: &eui48::MacAddress) -> String {
  mac.to_hexadecimal()[2..8].to_uppercase()
}

fn read_dhcpd_leases() -> Result<IPToDhcpdLease, Box<std::error::Error>> {

  let dhcpd_lease_file_name = match std::env::var("DHCPD_LEASES_FILE") {
    Ok(val) => Cow::from(val),
    Err(_) => Cow::from("/var/lib/dhcp/dhcpd.leases")
  };

  println!("dhcpd_lease_file_name = {}", dhcpd_lease_file_name);

  let file = File::open(dhcpd_lease_file_name.into_owned())?;

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

fn get_oui_set(ip_to_dhcpd_lease: &IPToDhcpdLease) -> OuiSet {

  let mut oui_set = OuiSet::default();

  for (_, dhcpd_lease) in ip_to_dhcpd_lease {
    if let Some(ref mac) = dhcpd_lease.mac {
      oui_set.insert(mac_to_oui(mac));
    }
  }

  oui_set

}

fn read_oui_file(oui_set: &OuiSet) -> Result<OuiToOrganization, Box<std::error::Error>> {

  let oui_file_name = match std::env::var("OUI_FILE") {
    Ok(val) => Cow::from(val),
    Err(_) => Cow::from("/usr/local/etc/oui.txt")
  };

  println!("oui_file_name = {}", oui_file_name);

  let file = File::open(oui_file_name.into_owned())?;

  let buf_reader = BufReader::new(&file);

  let re = Regex::new(r"^([[:xdigit:]]{6})\s+\(base\s16\)\s+(\S.*)$")?;

  let mut oui_set_mut = oui_set.clone();

  let mut oui_to_organization = OuiToOrganization::default();

  if !oui_set_mut.is_empty() {
    for line in buf_reader.lines() {
      let line_string = line?;

      if line_string.is_empty() ||
         (line_string.chars().nth(0) == Some('\t')) ||
         (line_string.chars().nth(3) == Some('-')) {
        continue;
      }

      match re.captures(&line_string) {
        Some(c) => {
          let oui = c.get(1).map_or("", |m| m.as_str()).to_uppercase();
          if oui_set_mut.contains(&oui) {
            oui_set_mut.remove(&oui);
            let organization = c.get(2).map_or("", |m| m.as_str()).to_string();
            oui_to_organization.insert(oui, organization);
          }
        },
        None => {}
      }

      if oui_set_mut.is_empty() {
        break;
      }
    }
  }

  Ok(oui_to_organization)
}


fn main() {

  let ip_to_dhcpd_lease = read_dhcpd_leases().expect("error reading dhcpd.leases");

  let oui_set = get_oui_set(&ip_to_dhcpd_lease);

  let oui_to_organization = match read_oui_file(&oui_set) {
    Ok(o) => o,
    Err(e) => {
      println!("error reading oui file {}", e);
      OuiToOrganization::default()
    }
  };

  println!("\n{:18}{:28}{:20}{:24}{}", "IP", "End Time", "MAC", "Hostname", "Organization");
  println!("====================================================================================================================");

  let mut ips: Vec<_> = ip_to_dhcpd_lease.keys().collect();
  ips.sort();

  for ip in ips {
    let lease = ip_to_dhcpd_lease.get(ip).unwrap();

    let end = match lease.end {
      Some(ref end) => Cow::from(end.to_string()),
      None => Cow::from("NA")
    };

    let mac = match lease.mac {
      Some(ref mac) => Cow::from(mac.to_hex_string()),
      None => Cow::from("NA")
    };

    let hostname = match lease.hostname {
      Some(ref hostname) => Cow::from(hostname.clone()),
      None => Cow::from("NA")
    };

    let organization = match lease.mac {
      Some(ref mac) => {
        let oui = mac_to_oui(mac);
        match oui_to_organization.get(&oui) {
          Some(organization) => Cow::from(organization.clone()),
          None => Cow::from("NA")
        }
      },
      None => Cow::from("NA")
    };

    println!("{:18}{:28}{:20}{:24}{}", ip, end, mac, hostname, organization);
  }
}

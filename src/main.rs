extern crate chrono;
#[macro_use]
extern crate enum_map;
extern crate eui48;
extern crate fnv;

use chrono::prelude::{DateTime, Local, TimeZone, Utc};

use fnv::FnvHashMap;
use fnv::FnvHashSet;

use std::borrow::Cow;
use std::default::Default;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::IpAddr;
use std::slice::Iter;
use std::str::FromStr;

type Oui = u32;

type OuiToOrganization = FnvHashMap<Oui, String>;

#[derive(Debug)]
struct DhcpdLease {
    ip: IpAddr,
    start: Option<DateTime<Local>>,
    end: Option<DateTime<Local>>,
    mac: Option<eui48::MacAddress>,
    hostname: Option<String>,
    abandoned: bool,
}

impl DhcpdLease {
    fn new(ip: IpAddr) -> Self {
        DhcpdLease {
            ip,
            start: None,
            end: None,
            mac: None,
            hostname: None,
            abandoned: false,
        }
    }

    fn is_after(&self, other_option: Option<&DhcpdLease>) -> bool {
        match other_option {
            Some(other) => {
                self.end.unwrap_or_else(|| Local.timestamp(0, 0))
                    >= other.end.unwrap_or_else(|| Local.timestamp(0, 0))
            }
            None => true,
        }
    }
}

type IPToDhcpdLease = FnvHashMap<IpAddr, DhcpdLease>;

type OuiSet = FnvHashSet<Oui>;

fn str_to_oui(s: &str) -> Result<Oui, std::num::ParseIntError> {
    Oui::from_str_radix(s, 16)
}

fn mac_to_oui(mac: &eui48::MacAddress) -> Oui {
    str_to_oui(&mac.to_hexadecimal()[2..8]).expect("error parsing oui")
}

fn read_dhcpd_leases() -> Result<IPToDhcpdLease, Box<std::error::Error>> {
    let dhcpd_lease_file_name = match std::env::var("DHCPD_LEASES_FILE") {
        Ok(val) => Cow::from(val),
        Err(_) => Cow::from("/var/lib/dhcp/dhcpd.leases"),
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
                let ip = IpAddr::from_str(split[1]).expect("invalid ip address");
                current_lease_option = Some(DhcpdLease::new(ip));
            }
        } else {
            if (split.len() >= 1) && (split[0] == "}") {
                if let Some(current_lease) = current_lease_option {
                    if current_lease.is_after(ip_to_dhcpd_lease.get(&current_lease.ip)) {
                        ip_to_dhcpd_lease.insert(current_lease.ip.clone(), current_lease);
                    }
                }
                current_lease_option = None;
            } else if (split.len() >= 4) && (split[0] == "starts") {
                if let Some(current_lease) = current_lease_option.as_mut() {
                    let mut date_time_string = String::new();
                    date_time_string.push_str(&split[2]);
                    date_time_string.push(' ');
                    date_time_string.push_str(split[3].trim_matches(';'));

                    let utc_datetime =
                        Utc.datetime_from_str(&date_time_string, "%Y/%m/%d %H:%M:%S")?;

                    let local_datetime = utc_datetime.with_timezone(&Local);

                    current_lease.start = Some(local_datetime);
                }
            } else if (split.len() >= 4) && (split[0] == "ends") {
                if let Some(current_lease) = current_lease_option.as_mut() {
                    let mut date_time_string = String::new();
                    date_time_string.push_str(&split[2]);
                    date_time_string.push(' ');
                    date_time_string.push_str(split[3].trim_matches(';'));

                    let utc_datetime =
                        Utc.datetime_from_str(&date_time_string, "%Y/%m/%d %H:%M:%S")?;

                    let local_datetime = utc_datetime.with_timezone(&Local);

                    current_lease.end = Some(local_datetime);
                }
            } else if (split.len() >= 3) && (split[0] == "hardware") && (split[1] == "ethernet") {
                if let Some(current_lease) = current_lease_option.as_mut() {
                    let mac_address = eui48::MacAddress::parse_str(split[2].trim_matches(';'))?;
                    current_lease.mac = Some(mac_address);
                }
            } else if (split.len() >= 2) && (split[0] == "client-hostname") {
                if let Some(current_lease) = current_lease_option.as_mut() {
                    let hostname = split[1].trim_matches('"').to_string();
                    let hostname = hostname.trim_matches(';').to_string();
                    let hostname = hostname.trim_matches('"').to_string();
                    current_lease.hostname = Some(hostname);
                }
            } else if (split.len() >= 3)
                && (split[0] == "binding")
                && (split[1] == "state")
                && (split[2] == "abandoned;")
            {
                if let Some(current_lease) = current_lease_option.as_mut() {
                    current_lease.abandoned = true;
                }
            }
        }
    }

    Ok(ip_to_dhcpd_lease)
}

fn get_oui_set(ip_to_dhcpd_lease: &IPToDhcpdLease) -> OuiSet {
    let mut oui_set = OuiSet::default();

    for dhcpd_lease in ip_to_dhcpd_lease.values() {
        if let Some(ref mac) = dhcpd_lease.mac {
            oui_set.insert(mac_to_oui(mac));
        }
    }

    oui_set
}

fn read_oui_file(mut oui_set: OuiSet) -> Result<OuiToOrganization, Box<std::error::Error>> {
    let oui_file_name = match std::env::var("OUI_FILE") {
        Ok(val) => Cow::from(val),
        Err(_) => Cow::from("/usr/local/etc/oui.txt"),
    };

    println!("oui_file_name = {}", oui_file_name);

    let file = File::open(oui_file_name.into_owned())?;

    let buf_reader = BufReader::new(&file);

    let mut oui_to_organization = OuiToOrganization::default();

    if !oui_set.is_empty() {
        for line in buf_reader.lines() {
            let line_string = line?;

            if (line_string.len() < 23)
                || (line_string.chars().nth(0) == Some('\t'))
                || (line_string.chars().nth(2) == Some('-'))
            {
                continue;
            }

            match str_to_oui(&line_string[0..6]) {
                Ok(oui) => {
                    if oui_set.remove(&oui) {
                        let organization = &line_string[22..];
                        oui_to_organization.insert(oui, organization.to_string());
                    }
                }
                Err(_) => {}
            }

            if oui_set.is_empty() {
                break;
            }
        }
    }

    Ok(oui_to_organization)
}

#[derive(Copy, Clone, Debug, EnumMap)]
enum DhcpLeaseState {
    Abandoned,
    Future,
    Current,
    Past,
}

impl DhcpLeaseState {
    pub fn iterator() -> Iter<'static, DhcpLeaseState> {
        static VALUES: [DhcpLeaseState; 4] = [
            DhcpLeaseState::Abandoned,
            DhcpLeaseState::Future,
            DhcpLeaseState::Current,
            DhcpLeaseState::Past,
        ];
        VALUES.into_iter()
    }

    pub fn to_string(self) -> &'static str {
        match self {
            DhcpLeaseState::Abandoned => "Abandoned",
            DhcpLeaseState::Future => "Future",
            DhcpLeaseState::Current => "Current",
            DhcpLeaseState::Past => "Past",
        }
    }
}

fn get_dhcp_lease_state(dhcpd_lease: &DhcpdLease) -> DhcpLeaseState {
    let now = Local::now();
    let lease_start = dhcpd_lease.start.unwrap_or_else(|| Local.timestamp(0, 0));
    let lease_end = dhcpd_lease.end.unwrap_or_else(|| Local.timestamp(0, 0));

    if dhcpd_lease.abandoned {
        DhcpLeaseState::Abandoned
    } else if now < lease_start {
        DhcpLeaseState::Future
    } else if (lease_start <= now) && (now <= lease_end) {
        DhcpLeaseState::Current
    } else {
        DhcpLeaseState::Past
    }
}

static NA_STRING: &'static str = "NA";

fn print_report(ip_to_dhcpd_lease: IPToDhcpdLease, oui_to_organization: OuiToOrganization) {
    println!(
        "\n{:18}{:11}{:28}{:20}{:24}{}",
        "IP", "State", "End Time", "MAC", "Hostname", "Organization"
    );
    for _ in 0..128 {
        print!("=");
    }
    println!();

    let mut state_to_count = enum_map! {
      _ => 0
    };

    let mut ips: Vec<_> = ip_to_dhcpd_lease.keys().collect();
    ips.sort();

    for ip in ips {
        let lease = ip_to_dhcpd_lease.get(ip).unwrap();

        let state = get_dhcp_lease_state(&lease);

        let state_string = state.to_string();

        state_to_count[state] += 1;

        let end = match lease.end {
            Some(ref end) => Cow::from(end.to_string()),
            None => Cow::from(NA_STRING),
        };

        let mac = match lease.mac {
            Some(ref mac) => Cow::from(mac.to_hex_string()),
            None => Cow::from(NA_STRING),
        };

        let hostname = match lease.hostname {
            Some(ref hostname) => Cow::from(hostname.clone()),
            None => Cow::from(NA_STRING),
        };

        let organization = match lease.mac {
            Some(ref mac) => {
                let oui = mac_to_oui(mac);
                match oui_to_organization.get(&oui) {
                    Some(organization) => Cow::from(organization.clone()),
                    None => Cow::from(NA_STRING),
                }
            }
            None => Cow::from(NA_STRING),
        };

        println!(
            "{:18}{:11}{:28}{:20}{:24}{}",
            ip.to_string(),
            state_string,
            end,
            mac,
            hostname,
            organization
        );
    }

    println!("\n{} leases with unique IPs:", ip_to_dhcpd_lease.len());
    for state in DhcpLeaseState::iterator() {
        println!("\t{} {}", state_to_count[*state], state.to_string());
    }
}

fn main() {
    let ip_to_dhcpd_lease = read_dhcpd_leases().expect("error reading dhcpd.leases");

    let oui_set = get_oui_set(&ip_to_dhcpd_lease);

    let oui_to_organization = match read_oui_file(oui_set) {
        Ok(o) => o,
        Err(e) => {
            println!("error reading oui file {}", e);
            OuiToOrganization::default()
        }
    };

    print_report(ip_to_dhcpd_lease, oui_to_organization);
}

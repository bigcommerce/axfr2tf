extern crate trust_dns; 
extern crate clap; 
extern crate itertools;
extern crate chrono;
extern crate log;
extern crate env_logger;

use std::str::FromStr;
use std::io::{ self, Write }; 

use trust_dns::client::{Client, SyncClient};
use trust_dns::tcp::TcpClientConnection;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RecordType};

use itertools::Itertools;

use clap::{Arg, App};

use chrono::{DateTime, Utc};

mod convert; 

fn validate_zone_arg(zone: String) -> Result<(), String> { 
    if zone.ends_with(".") { 
        Ok(())
    } else { 
        Err(String::from("Zone must be fully-qualified and end in a period ('.')."))
    }
}

fn main() -> std::io::Result<()> {
    env_logger::init(); 

    let matches = App::new("axfr2tf")
                          .version("0.1")
                          .about("Converts records from an AXFR query to Terraform resources")
                          .arg(Arg::with_name("nameserver")
                               .short("n")
                               .long("nameserver")
                               .help("What nameserver IP to query (e.g., 127.0.0.1:53)")
                               .takes_value(true)
                               .required(true))
                          .arg(Arg::with_name("zone") //TODO check for trailing period
                               .short("z")
                               .long("zone")
                               .help("What zone to query for (e.g. bigcommerce.com.)")
                               .validator(validate_zone_arg)
                               .takes_value(true)
                               .required(true))
                          .arg(Arg::with_name("resource")
                               .short("r")
                               .long("resource")
                               .help("Sets what TF zone resource to assign records to")
                               .takes_value(true)
                               .required(true))
                          .get_matches();

    let tf_zone_resource = matches.value_of("resource").unwrap(); 
    let dns_server_addr = matches.value_of("nameserver").unwrap(); 
    let axfr_host = matches.value_of("zone").unwrap();
    let address = dns_server_addr.parse().unwrap();

    //NB: TCP required for AXFR
    let conn = TcpClientConnection::new(address).unwrap(); 

    let client = SyncClient::new(conn);
    let name = Name::from_str(axfr_host).unwrap();

    // run axfr query
    let response: DnsResponse = 
        match client.query(&name, DNSClass::IN, RecordType::AXFR) { 
            Ok(resp) => resp,
            Err(err) => panic!("error executing dns query: {:?}", err),
        };

    write_header_block(&mut std::io::stdout())?;
    write_zone(&mut std::io::stdout(), tf_zone_resource, &name)?;

    for m in response.messages() { 
        // group consecutive records together so they can be
        // written as one terraform resource
        let gm = m.answers().into_iter().group_by(|g| { 
            format!("{},{}", g.record_type(), g.name())
        });

        for (_,rs) in gm.into_iter() { 
            convert::write_record(&name, String::from(tf_zone_resource), &mut rs.into_iter(), &mut std::io::stdout())?
        }
    }

    Ok(())
}

fn write_zone<W: Write>(out: &mut W, zone_resource: &str, dns_name: &Name) -> io::Result<()> { 
    write!(out, "resource \"google_dns_managed_zone\" \"{}\" {{\n", zone_resource)?; 
    write!(out, "  name = \"{}\"\n", String::from(zone_resource).replace("_", "-"))?;
    write!(out, "  dns_name = \"{}\"\n", dns_name)?;
    write!(out, "}}\n\n")?;
    Ok(())
}

fn write_header_block<W: Write>(out: &mut W) -> io::Result<()> { 
    let now: DateTime<Utc> = Utc::now();
    write!(out, "# Auto-generated by axfr2tf on {}\n\n", now)?;
    Ok(())
}

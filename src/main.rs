extern crate trust_dns; 
extern crate clap; 
extern crate itertools;

use std::str::FromStr;
use trust_dns::client::{Client, SyncClient};
use trust_dns::tcp::TcpClientConnection;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RecordType};

use itertools::Itertools;

use clap::{Arg, App};

mod convert; 

fn main() -> std::io::Result<()> {
    let matches = App::new("axfr2tf")
                          .version("0.1")
                          .about("Converts records from an AXFR query to Terraform resources")
                          .arg(Arg::with_name("nameserver")
                               .short("n")
                               .long("nameserver")
                               .help("What nameserver IP to query (e.g., 127.0.0.1:53)")
                               .takes_value(true)
                               .required(true))
                          .arg(Arg::with_name("zone")
                               .short("z")
                               .long("zone")
                               .help("What zone to query for (e.g. bigcommerce.com)")
                               .takes_value(true)
                               .required(true))
                          .arg(Arg::with_name("resource")
                               .short("r")
                               .long("resource")
                               .help("Sets what TF zone resource to assign records to")
                               .takes_value(true)
                               .required(true))
                          .get_matches();

    //TODO from arg
    let tf_zone_resource = matches.value_of("resource").unwrap(); 

    //TODO from arg -- this is dyn
    let dns_server_addr = matches.value_of("nameserver").unwrap(); 

    //TODO from arg 
    let axfr_host = matches.value_of("zone").unwrap();

    //dynect
    let address = dns_server_addr.parse().unwrap();

    //NB: TCP required for AXFR
    let conn = TcpClientConnection::new(address).unwrap();
    let client = SyncClient::new(conn);

    //dig AXFR bigcommerce.net @xfrout1.dynect.net
    let name = Name::from_str(axfr_host).unwrap();

    // run axfr query
    let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::AXFR).unwrap();

    for m in response.messages() { 
        // group consecutive records together so they can be
        // written as one terraform resource
        let gm = m.answers().into_iter().group_by(|g| { 
            format!("{},{}", g.record_type(), g.name())
        });

        for (_,rs) in gm.into_iter() { 
            convert::write_record(String::from(tf_zone_resource), &mut rs.into_iter(), &mut std::io::stdout())?
        }
    }

    Ok(())
}

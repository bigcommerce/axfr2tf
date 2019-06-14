use trust_dns::rr::{Name, RData, Record, RecordType};
use std::io::{self, Write}; 

fn write_record_data<'a, W: Write, I: Iterator<Item = &'a RData>>(
    rrdatas: I, 
    out: &mut W) -> io::Result<()> { 

    write!(out, "\trrdatas = [ \n")?; 
    
    for d in rrdatas { 
        (match d {
            RData::A(ip) => { 
                write!(out, "\t\t\"{:?}\",\n", ip)?;
                Ok::<(), io::Error>(())
            }
            RData::MX(mx) => { 
                write!(out, "\t\t\"{} {}\",\n", mx.preference(), mx.exchange())?;
                Ok::<(), io::Error>(())
            }
            RData::CNAME(name) => {
                write!(out, "\t\t\"{}\",\n", name)?;
                Ok::<(), io::Error>(())
            }
            _ => Ok::<(), io::Error>(()),
        })?;
    }

    write!(out, "\t]\n")?;

    Ok(())
}

fn write_record_info<'a, W: Write,I: Iterator<Item = &'a Record>>(
    zone_resource :String,
    record_type: &RecordType, 
    record_name: &Name, 
    record_ttl: u32,
    rs: I, 
    out: &mut W) -> io::Result<()> {

    let type_str: &str = (*record_type).into(); 

    write!(out, "resource \"google_dns_record_set\" \"{}\" {{\n", type_str.to_lowercase())?; 
    write!(out, "\tname = \"{}\"\n", record_name)?;
    write!(out, "\tmanaged_zone = \"${{{}}}\"\n", zone_resource)?;
    write!(out, "\ttype = \"{}\"\n", type_str)?;
    write!(out, "\tttl = {}\n", record_ttl)?;

    let rrdatas = rs.map(|r| r.rdata());

    write_record_data(rrdatas, out)?;

    write!(out, "}}\n\n")?;

    Ok(())
}

pub fn write_record<'a, W: Write, I: Iterator<Item = &'a Record>>(
    zone_tf_resource: String, 
    rs: &mut I, 
    out: &mut W) -> io::Result<()> {

    let records: Vec<&Record> = rs.collect(); 
         
    let (record_type, record_name, record_ttl) = { 
        let r = records[0];
        (r.record_type(), r.name(), r.ttl())
    };

    match record_type { 
        RecordType::A | RecordType::CNAME | RecordType::TXT | RecordType::MX => { 
            write_record_info(
                zone_tf_resource,
                &record_type,
                record_name,
                record_ttl,
                records.into_iter(),
                out
            )
        }
        _ => Ok(())
    }
}
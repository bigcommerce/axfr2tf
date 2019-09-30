use trust_dns::rr::{Name, RData, Record, RecordType};
use std::io::{self, Write}; 

fn write_record_data<'a, W: Write, I: Iterator<Item = &'a RData>>(
    rrdatas: I, 
    out: &mut W) -> io::Result<()> { 

    write!(out, "  rrdatas = [\n")?; 
    
    for d in rrdatas { 
        (match d {
            RData::A(ip) => { 
                write!(out, "    \"{:?}\",\n", ip)?;
                Ok::<(), io::Error>(())
            }
            RData::MX(mx) => { 
                write!(out, "    \"{} {}\",\n", mx.preference(), mx.exchange())?;
                Ok::<(), io::Error>(())
            }
            RData::CNAME(name) => {
                write!(out, "    \"{}\",\n", name)?;
                Ok::<(), io::Error>(())
            }
            RData::NS(name) => { 
                write!(out, "    \"{}\",\n", name)?;
                Ok::<(), io::Error>(())
            }
            RData::TXT(txt) => { 
                let txt_data = txt.txt_data(); 

                write!(out, "    \"")?;

                for txt_block in txt_data {
                    let contains_space = txt_block.contains(&b' '); 
                    let mut txt = Vec::new(); 
                    let mut i: u32 = 0;

                    if contains_space { 
                        txt.push('\\');
                        txt.push('"');
                    }

                    for c in txt_block.into_iter() { 

                        // From TF docs: 
                        // To specify a single record value longer than 255 characters such as a 
                        // TXT record for DKIM, add \"\" inside the Terraform configuration 
                        // string (e.g. "first255characters\"\"morecharacters").
                        // 
                        // https://www.terraform.io/docs/providers/google/r/dns_record_set.html#rrdatas
                        if i > 0 && i % 255 == 0 { 
                            txt.push('\\');
                            txt.push('"');
                            txt.push('\\');
                            txt.push('"');
                        }

                        match c { 
                            &c if (c as char) == '"' => { 
                                txt.push('\\');
                                txt.push('"');
                            }
                            &c => txt.push(c as char),
                        }

                        i += 1;
                    }

                    if contains_space { 
                        txt.push('\\');
                        txt.push('"');
                    }

                    write!(out,"{}",txt.into_iter().collect::<String>())?; 
                }

                write!(out, "\",\n")?;

                Ok::<(), io::Error>(())
            }
            _ => Ok::<(), io::Error>(()),
        })?;
    }

    write!(out, "  ]\n")?;

    Ok(())
}

fn record_resource_name(record_name: &Name, record_type: &RecordType) -> String { 
    let mut record_name_str = record_name.to_utf8(); 
    record_name_str = record_name_str.replace(".", "_"); 

    if record_name_str.ends_with("_") { 
        record_name_str.pop();
    } 

    record_name_str = record_name_str.replace("*", "star"); 

    format!("dns_{}_{}", record_name_str, record_type)
}

fn write_record_info<'a, W: Write,I: Iterator<Item = &'a Record>>(
    zone_resource :String,
    record_type: &RecordType, 
    record_name: &Name, 
    record_ttl: u32,
    rs: I, 
    out: &mut W) -> io::Result<()> {

    let record_resource_name = record_resource_name(record_name, record_type);
    let type_str: &str = (*record_type).into(); 

    write!(out, "resource \"google_dns_record_set\" \"{}\" {{\n", record_resource_name)?; 
    write!(out, "  name = \"{}\"\n", record_name)?;
    write!(out, "  managed_zone = google_dns_managed_zone.{}.name\n", zone_resource)?;
    write!(out, "  type = \"{}\"\n", type_str)?;
    write!(out, "  ttl = {}\n", record_ttl)?;

    let rrdatas = rs.map(|r| r.rdata());

    write_record_data(rrdatas, out)?;

    write!(out, "}}\n\n")?;

    Ok(())
}

pub fn write_record<'a, W: Write, I: Iterator<Item = &'a Record>>(
    zone_dns_name: &Name,
    zone_tf_resource: String, 
    rs: &mut I, 
    out: &mut W) -> io::Result<()> {

    let records: Vec<&Record> = rs.collect(); 
         
    let (record_type, record_name, record_ttl) = { 
        let r = records[0];
        (r.record_type(), r.name(), r.ttl())
    };

    let should_write_record = 
        match record_type { 
            RecordType::A | RecordType::CNAME | RecordType::TXT | RecordType::MX => true,
            RecordType::NS if record_name != zone_dns_name => true,
            _ => false,
        };

    if should_write_record { 
        write_record_info(
            zone_tf_resource,
            &record_type,
            record_name,
            record_ttl,
            records.into_iter(),
            out
        )
    } else { 
        Ok(())
    }   
}
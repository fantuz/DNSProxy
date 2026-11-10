use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};

mod wire {
    include!("../../src/wire.rs");

    pub fn describe(status: Status, info: &Info) -> String {
        let code = match status {
            Status::Ok => 0,
            Status::Drop => 1,
            Status::FormErr => 2,
            Status::NotImp => 3,
        };
        if status == Status::Drop {
            return code.to_string();
        }
        format!(
            "{code} {} {} {} {} {} {} {} {} {} {} {}",
            info.question_end,
            info.final_opt_rdlen.unwrap_or(0),
            info.udp_limit,
            info.qtype,
            info.qclass,
            info.opcode,
            info.opt_ext_rcode,
            u8::from(info.has_opt),
            u8::from(info.opt_do),
            u8::from(info.signed),
            super::fingerprint(info.name.wire()),
        )
    }
}

fn fingerprint(data: &[u8]) -> u64 {
    data.iter().fold(14695981039346656037, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(1099511628211)
    })
}

fn main() -> io::Result<()> {
    let mut input = BufReader::new(io::stdin().lock());
    let mut output = BufWriter::new(io::stdout().lock());
    let mut header = [0; 11];
    while !input.fill_buf()?.is_empty() {
        input.read_exact(&mut header)?;
        let cap = wire::u16_at(&header, 0);
        let query_len = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
        let response_len = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;
        let mut query = vec![0; query_len];
        let mut response = vec![0; response_len];
        input.read_exact(&mut query)?;
        input.read_exact(&mut response)?;
        let (status, info) = wire::parse(&query, None, cap);
        write!(output, "{}", wire::describe(status, &info))?;
        if status == wire::Status::Ok {
            let padded = wire::padded_query(&query, &info);
            write!(
                output,
                " | {} {} {} {} {}",
                u8::from(wire::plain_address(&query, &info)),
                u8::from(wire::failover_eligible(&query, &info)),
                wire::cache_index(&query, &info, 17).map_or(-1, |slot| slot as i32),
                padded.as_ref().map_or(0, Vec::len),
                padded.as_deref().map_or(0, fingerprint),
            )?;
            if header[10] != 0 {
                let (status, reply) = wire::parse(&response, Some(&info), cap);
                write!(output, " | {}", wire::describe(status, &reply))?;
                if status == wire::Status::Ok {
                    if padded.is_some() {
                        wire::strip_padding(&mut response, &reply);
                    }
                    if let Some((offsets, ttl)) = wire::cache_ttls(&response, &reply) {
                        write!(output, " | {ttl}")?;
                        for offset in offsets {
                            write!(output, " {offset}")?;
                        }
                    }
                    wire::age_forwarded(&mut response, &reply, 17);
                    write!(output, " | {} {}", response.len(), fingerprint(&response))?;
                }
            }
        }
        writeln!(output)?;
    }
    output.flush()
}

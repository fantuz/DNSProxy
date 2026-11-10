use std::ops::Range;

pub const HEADER: usize = 12;
pub const TCP_MAX: usize = u16::MAX as usize;
pub const UDP_RX_MAX: usize = 65_507;
pub const UDP_REPLY_MAX: u16 = 4096;
pub const UDP_REPLY_DEFAULT: u16 = 1232;
const OPT_SIZE: usize = 11;
const MAX_POINTER_HOPS: usize = 128;
const CACHE_MAX_QUERY: usize = HEADER + 255 + 4 + OPT_SIZE;
const CACHE_MAX_REPLY: usize = 4096;
const CACHE_MAX_ANSWERS: usize = 128;
const PADDING: u16 = 12;
const PADDING_BLOCK: usize = 128;

#[derive(Clone)]
struct Name {
    bytes: [u8; 255],
    len: usize,
}

impl Default for Name {
    fn default() -> Self {
        Self {
            bytes: [0; 255],
            len: 0,
        }
    }
}

impl Name {
    fn wire(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone)]
pub struct Info {
    pub question_end: usize,
    final_opt_rdlen: Option<usize>,
    pub udp_limit: usize,
    qtype: u16,
    qclass: u16,
    name: Name,
    opcode: u8,
    pub opt_ext_rcode: u8,
    has_opt: bool,
    opt_do: bool,
    pub signed: bool,
}

impl Default for Info {
    fn default() -> Self {
        Self {
            question_end: HEADER,
            final_opt_rdlen: None,
            udp_limit: 512,
            qtype: 0,
            qclass: 0,
            name: Name::default(),
            opcode: 0,
            opt_ext_rcode: 0,
            has_opt: false,
            opt_do: false,
            signed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Drop,
    FormErr,
    NotImp,
}

pub fn u16_at(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

fn u32_at(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]])
}

fn put_u16(p: &mut [u8], at: usize, value: u16) {
    p[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

// Validate the expanded length even when the caller only needs the wire end.
fn read_name(
    p: &[u8],
    offset: &mut usize,
    compression: bool,
    remaining_pointers: &mut usize,
    mut output: Option<&mut Name>,
) -> Option<()> {
    let mut at = *offset;
    let mut end = None;
    let mut used = 0;
    let mut hops = 0;
    loop {
        let len = *p.get(at)? as usize;
        if len & 0xc0 == 0xc0 {
            if !compression || hops == MAX_POINTER_HOPS || *remaining_pointers == 0 {
                return None;
            }
            let target = ((len & 0x3f) << 8) | *p.get(at + 1)? as usize;
            if target < HEADER || target >= at {
                return None;
            }
            hops += 1;
            *remaining_pointers -= 1;
            end.get_or_insert(at + 2);
            at = target;
            continue;
        }
        let next = at + 1 + len;
        if len > 63 || used + 1 + len > 255 {
            return None;
        }
        let label = p.get(at + 1..next)?;
        if let Some(name) = output.as_deref_mut() {
            name.bytes[used] = len as u8;
            for (out, c) in name.bytes[used + 1..used + 1 + len].iter_mut().zip(label) {
                *out = c.to_ascii_lowercase();
            }
        }
        used += 1 + len;
        at = next;
        if len == 0 {
            *offset = end.unwrap_or(at);
            if let Some(name) = output {
                name.len = used;
            }
            return Some(());
        }
    }
}

fn rr_names(
    p: &[u8],
    start: usize,
    end: usize,
    kind: u16,
    remaining_pointers: &mut usize,
) -> Option<()> {
    let (prefix, tail, names, compressed) = match kind {
        2 | 5 | 12 => (0, 0, 1, true), // NS, CNAME, PTR
        6 => (0, 20, 2, true),         // SOA
        15 => (2, 0, 1, true),         // MX
        33 => (6, 0, 1, true),         // SRV compatibility
        39 => (0, 0, 1, false),        // DNAME
        _ => return Some(()),          // Opaque RDATA
    };
    if end - start < prefix + tail {
        return None;
    }
    let mut pos = start + prefix;
    let limit = end - tail;
    for _ in 0..names {
        read_name(&p[..limit], &mut pos, compressed, remaining_pointers, None)?;
    }
    (pos == limit).then_some(())
}

fn options_valid(mut options: &[u8]) -> bool {
    while !options.is_empty() {
        if options.len() < 4 {
            return false;
        }
        let Some(rest) = options.get(4 + u16_at(options, 2) as usize..) else {
            return false;
        };
        options = rest;
    }
    true
}

pub fn parse(p: &[u8], request: Option<&Info>, cap: u16) -> (Status, Info) {
    let mut info = Info::default();
    let status = parse_into(p, request, cap, &mut info);
    (status, info)
}

fn parse_into(p: &[u8], request: Option<&Info>, cap: u16, info: &mut Info) -> Status {
    let response = request.is_some();
    if !(HEADER..=TCP_MAX).contains(&p.len()) || ((p[2] & 0x80 != 0) != response) {
        return Status::Drop;
    }
    info.opcode = p[2] & 0x78;
    if let Some(query) = request {
        if info.opcode != query.opcode {
            return Status::FormErr;
        }
    } else if info.opcode != 0 {
        return Status::NotImp;
    }

    let questions = u16_at(p, 4);
    if questions > 1 || p[3] & 0x40 != 0 || (!response && p[3] & 15 != 0) {
        return Status::FormErr;
    }
    let mut pos = HEADER;
    let mut pointer_budget = p.len();
    if questions != 0 {
        if read_name(
            p,
            &mut pos,
            response,
            &mut pointer_budget,
            Some(&mut info.name),
        )
        .is_none()
            || pos + 4 > p.len()
        {
            return Status::FormErr;
        }
        info.qtype = u16_at(p, pos);
        info.qclass = u16_at(p, pos + 2);
        pos += 4;
        info.question_end = pos;
        if let Some(query) = request {
            if info.name.wire() != query.name.wire()
                || info.qtype != query.qtype
                || info.qclass != query.qclass
            {
                return Status::FormErr;
            }
        }
    }

    let counts = [u16_at(p, 6), u16_at(p, 8), u16_at(p, 10)];
    let transfer = !response && matches!(info.qtype, 251 | 252);
    if !response && !transfer && (counts[0] != 0 || counts[1] != 0) {
        return Status::FormErr;
    }
    for (section, count) in counts.into_iter().enumerate() {
        for i in 0..count {
            let owner = pos;
            if read_name(p, &mut pos, true, &mut pointer_budget, None).is_none()
                || pos + 10 > p.len()
            {
                return Status::FormErr;
            }
            let kind = u16_at(p, pos);
            let class = u16_at(p, pos + 2);
            let len = u16_at(p, pos + 8) as usize;
            let rdlen_at = pos + 8;
            if section == 2 && matches!(kind, 24 | 250) {
                info.signed = true;
            }
            let ext = p[pos + 4];
            let version = p[pos + 5];
            let do_bit = p[pos + 6] & 0x80 != 0;
            pos += 10;
            let end = pos + len;
            if kind == 41 {
                if section != 2 || info.has_opt {
                    return Status::FormErr;
                }
                // Keep enough OPT metadata for an EDNS-aware FORMERR.
                info.has_opt = true;
                info.opt_ext_rcode = ext;
                info.opt_do = do_bit;
                if !response {
                    info.udp_limit = usize::from(class.max(512).min(cap));
                }
                if i + 1 == counts[2] && version == 0 && (response || ext == 0) {
                    info.final_opt_rdlen = Some(rdlen_at);
                }
                if p[owner] != 0 || !p.get(pos..end).is_some_and(options_valid) {
                    return Status::FormErr;
                }
            } else if end > p.len() || rr_names(p, pos, end, kind, &mut pointer_budget).is_none() {
                return Status::FormErr;
            }
            pos = end;
        }
    }
    if pos != p.len() {
        return Status::FormErr;
    }
    if let Some(query) = request {
        if info.has_opt && !query.has_opt {
            return Status::FormErr;
        }
        if questions == 0
            && query.name.len != 0
            && p[2] & 2 == 0
            && p[3] & 15 == 0
            && info.opt_ext_rcode == 0
        {
            return Status::FormErr;
        }
    }
    if transfer { Status::NotImp } else { Status::Ok }
}

fn append_opt(p: &mut Vec<u8>, info: &Info, extended_rcode: u8) {
    if !info.has_opt {
        return;
    }
    let [high, low] = UDP_REPLY_MAX.to_be_bytes();
    p[11] = 1;
    p.extend_from_slice(&[
        0,
        0,
        41,
        high,
        low,
        extended_rcode,
        0,
        if info.opt_do { 0x80 } else { 0 },
        0,
        0,
        0,
    ]);
}

pub fn error_reply(request: &[u8], info: &Info, rcode: u8) -> Vec<u8> {
    let mut p = request[..info.question_end].to_vec();
    p[2] = (p[2] & 0x79) | 0x80;
    p[3] = (p[3] & 0x10) | (rcode & 15);
    if info.question_end == HEADER {
        p[4..6].fill(0);
    }
    p[6..12].fill(0);
    append_opt(&mut p, info, 0);
    p
}

pub fn truncated_reply(request: &[u8], query: &Info, response: &[u8], reply: &Info) -> Vec<u8> {
    let mut p = response[..HEADER].to_vec();
    p[2] |= 2;
    p[3] &= !0x20;
    p[4] = 0;
    p[5] = u8::from(query.question_end > HEADER);
    p[6..12].fill(0);
    p.extend_from_slice(&request[HEADER..query.question_end]);
    append_opt(&mut p, query, reply.opt_ext_rcode);
    p
}

pub fn satisfies(response: &[u8], info: &Info) -> bool {
    response[2] & 2 == 0 && info.opt_ext_rcode == 0 && matches!(response[3] & 15, 0 | 3)
}

fn empty_opt(p: &[u8]) -> bool {
    p.len() == OPT_SIZE && p[0] == 0 && u16_at(p, 1) == 41 && u32_at(p, 5) == 0 && u16_at(p, 9) == 0
}

pub fn plain_address(p: &[u8], info: &Info) -> bool {
    u16_at(p, 4) == 1
        && info.qclass == 1
        && matches!(info.qtype, 1 | 28)
        && p[2] == 1
        && p[3] & !0x20 == 0
}

pub fn cache_index(p: &[u8], info: &Info, entries: usize) -> Option<usize> {
    if entries == 0 || p.len() > CACHE_MAX_QUERY || !plain_address(p, info) {
        return None;
    }
    let additional = u16_at(p, 10);
    if additional != 0 && (additional != 1 || !empty_opt(&p[info.question_end..])) {
        return None;
    }
    let hash = p[2..].iter().fold(2_166_136_261u32, |h, b| {
        (h ^ u32::from(*b)).wrapping_mul(16_777_619)
    });
    Some(hash as usize % entries)
}

pub fn cache_ttls(p: &[u8], info: &Info) -> Option<(Vec<usize>, u32)> {
    let answers = usize::from(u16_at(p, 6));
    if p.len() > CACHE_MAX_REPLY
        || p[2] & 2 != 0
        || p[3] & 15 != 0
        || u16_at(p, 4) != 1
        || u16_at(p, 8) != 0
        || !(1..=CACHE_MAX_ANSWERS).contains(&answers)
    {
        return None;
    }
    let mut offsets = Vec::with_capacity(answers);
    let mut min_ttl = u32::MAX;
    let mut pos = info.question_end;
    let mut pointer_budget = p.len();
    let mut has_address = false;
    for _ in 0..answers {
        read_name(p, &mut pos, true, &mut pointer_budget, None)?;
        if pos + 10 > p.len() {
            return None;
        }
        let kind = u16_at(p, pos);
        let len = u16_at(p, pos + 8) as usize;
        if pos + 10 + len > p.len() || u16_at(p, pos + 2) != 1 || (kind != 5 && kind != info.qtype)
        {
            return None;
        }
        if kind == info.qtype {
            if len != if kind == 1 { 4 } else { 16 } {
                return None;
            }
            has_address = true;
        }
        let ttl = u32_at(p, pos + 4);
        min_ttl = min_ttl.min(if ttl <= i32::MAX as u32 { ttl } else { 0 });
        offsets.push(pos + 4);
        pos += 10 + len;
    }
    (has_address && (pos == p.len() || (u16_at(p, 10) == 1 && empty_opt(&p[pos..]))))
        .then_some((offsets, min_ttl))
}

pub fn age_ttl(p: &mut [u8], at: usize, age: u64) {
    let ttl = u32_at(p, at);
    let ttl = if ttl <= i32::MAX as u32 && u64::from(ttl) > age {
        ttl - age as u32
    } else {
        0
    };
    p[at..at + 4].copy_from_slice(&ttl.to_be_bytes());
}

pub fn age_forwarded(p: &mut [u8], info: &Info, age: u32) {
    if age == 0 || info.signed {
        return;
    }
    let records = [6, 8, 10]
        .into_iter()
        .map(|at| u16_at(p, at) as usize)
        .sum::<usize>();
    let mut pos = info.question_end;
    for _ in 0..records {
        // The validator checked each owner. Follow only its inline wire form.
        while p[pos] != 0 && p[pos] & 0xc0 == 0 {
            pos += 1 + p[pos] as usize;
        }
        pos += if p[pos] & 0xc0 != 0 { 2 } else { 1 };
        if u16_at(p, pos) != 41 {
            age_ttl(p, pos + 4, u64::from(age));
        }
        pos += 10 + u16_at(p, pos + 8) as usize;
    }
}

fn option_ranges(p: &[u8], mut pos: usize) -> impl Iterator<Item = Range<usize>> + '_ {
    std::iter::from_fn(move || {
        if pos >= p.len() {
            return None;
        }
        let start = pos;
        pos += 4 + u16_at(p, pos + 2) as usize;
        Some(start..pos)
    })
}

pub fn padded_query(p: &[u8], info: &Info) -> Option<Vec<u8>> {
    let at = info.final_opt_rdlen.filter(|_| !info.signed)?;
    if option_ranges(p, at + 2).any(|r| u16_at(p, r.start) == PADDING) {
        return None;
    }
    let extra = 4 + (PADDING_BLOCK - (p.len() + 4) % PADDING_BLOCK) % PADDING_BLOCK;
    if p.len() + extra > TCP_MAX {
        return None;
    }
    let mut out = Vec::with_capacity(p.len() + extra);
    out.extend_from_slice(p);
    put_u16(&mut out, at, u16_at(p, at) + extra as u16);
    out.extend_from_slice(&PADDING.to_be_bytes());
    out.extend_from_slice(&((extra - 4) as u16).to_be_bytes());
    out.resize(p.len() + extra, 0);
    Some(out)
}

pub fn strip_padding(p: &mut Vec<u8>, info: &Info) {
    let Some(at) = info.final_opt_rdlen.filter(|_| !info.signed) else {
        return;
    };
    let start = at + 2;
    let mut pos = start;
    let mut write = start;
    while pos < p.len() {
        let len = 4 + u16_at(p, pos + 2) as usize;
        if u16_at(p, pos) != PADDING {
            if write != pos {
                p.copy_within(pos..pos + len, write);
            }
            write += len;
        }
        pos += len;
    }
    put_u16(p, at, (write - start) as u16);
    p.truncate(write);
}

pub fn failover_eligible(p: &[u8], info: &Info) -> bool {
    if u16_at(p, 4) != 1 || info.qclass != 1 || matches!(info.qtype, 249 | 250) {
        return false;
    }
    let additional = u16_at(p, 10);
    additional == 0
        || (additional == 1 && info.final_opt_rdlen.is_some_and(|at| u16_at(p, at) == 0))
}

use crate::{native, wire};

const MAX_TTL: u32 = 3600;

struct Entry {
    key: Vec<u8>,
    reply: Vec<u8>,
    ttl_offsets: Vec<usize>,
    received_ms: u64,
    age_ms: u64,
    expires_ms: u64,
}

pub struct Cache(Vec<Option<Entry>>);

impl Cache {
    pub fn new(entries: usize) -> Self {
        Self((0..entries).map(|_| None).collect())
    }

    pub fn index(&self, request: &[u8], info: &wire::Info) -> Option<usize> {
        wire::cache_index(request, info, self.0.len())
    }

    pub fn lookup(
        &mut self,
        index: usize,
        request: &[u8],
        udp_limit: Option<usize>,
    ) -> Option<Vec<u8>> {
        let slot = &mut self.0[index];
        let entry = slot.as_ref()?;
        let now = native::boot_millis()?;
        if now < entry.received_ms || now >= entry.expires_ms {
            *slot = None;
            return None;
        }
        if entry.key != request[2..] || udp_limit.is_some_and(|max| entry.reply.len() > max) {
            return None;
        }
        let mut reply = entry.reply.clone();
        reply[..2].copy_from_slice(&request[..2]);
        let age = (entry.age_ms + now - entry.received_ms).div_ceil(1000);
        for &offset in &entry.ttl_offsets {
            wire::age_ttl(&mut reply, offset, age);
        }
        Some(reply)
    }

    pub fn store(
        &mut self,
        index: usize,
        request: &[u8],
        reply: &[u8],
        info: &wire::Info,
        age_ms: u64,
        max_age: u32,
    ) {
        let Some((ttl_offsets, min_ttl)) = wire::cache_ttls(reply, info) else {
            return;
        };
        let lifetime = u64::from(min_ttl.min(MAX_TTL).min(max_age)) * 1000;
        let Some(now) = native::boot_millis().filter(|&now| now != 0 && age_ms < lifetime) else {
            return;
        };
        self.0[index] = Some(Entry {
            key: request[2..].to_vec(),
            reply: reply.to_vec(),
            ttl_offsets,
            received_ms: now,
            age_ms,
            expires_ms: now + lifetime - age_ms,
        });
    }
}

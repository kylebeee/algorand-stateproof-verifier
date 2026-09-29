//! Minimal msgpack reader/writer for Algorand's canonical encoding.
//!
//! Algorand encodes structs as maps with sorted string keys, omits zero-valued fields,
//! encodes `[]byte` as `bin` and integers in their shortest unsigned form. The reader here
//! only accepts those forms.

use crate::error::{Error, Result};
use alloc::vec::Vec;

const MAX_DEPTH: usize = 64;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    fn peek(&self) -> Result<u8> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or(Error::Msgpack("unexpected end of input"))
    }

    fn byte(&mut self) -> Result<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Msgpack("length overflow"))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(Error::Msgpack("unexpected end of input"))?;
        self.pos = end;
        Ok(s)
    }

    fn be(&mut self, n: usize) -> Result<u64> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }

    pub fn is_nil(&self) -> bool {
        self.peek() == Ok(0xc0)
    }

    pub fn read_nil(&mut self) -> Result<()> {
        match self.byte()? {
            0xc0 => Ok(()),
            _ => Err(Error::Msgpack("expected nil")),
        }
    }

    pub fn read_map_len(&mut self) -> Result<usize> {
        match self.byte()? {
            b @ 0x80..=0x8f => Ok((b & 0x0f) as usize),
            0xde => Ok(self.be(2)? as usize),
            0xdf => Ok(self.be(4)? as usize),
            _ => Err(Error::Msgpack("expected map")),
        }
    }

    /// Map length, treating `nil` as an empty map (how Go encodes nil maps).
    pub fn read_map_len_or_nil(&mut self) -> Result<usize> {
        if self.is_nil() {
            self.pos += 1;
            return Ok(0);
        }
        self.read_map_len()
    }

    pub fn read_array_len(&mut self) -> Result<usize> {
        match self.byte()? {
            b @ 0x90..=0x9f => Ok((b & 0x0f) as usize),
            0xdc => Ok(self.be(2)? as usize),
            0xdd => Ok(self.be(4)? as usize),
            _ => Err(Error::Msgpack("expected array")),
        }
    }

    /// Array length, treating `nil` as an empty array (how Go encodes nil slices).
    pub fn read_array_len_or_nil(&mut self) -> Result<usize> {
        if self.is_nil() {
            self.pos += 1;
            return Ok(0);
        }
        self.read_array_len()
    }

    pub fn read_str(&mut self) -> Result<&'a [u8]> {
        let len = match self.byte()? {
            b @ 0xa0..=0xbf => (b & 0x1f) as usize,
            0xd9 => self.be(1)? as usize,
            0xda => self.be(2)? as usize,
            0xdb => self.be(4)? as usize,
            _ => return Err(Error::Msgpack("expected string")),
        };
        self.take(len)
    }

    /// `bin` payload; `nil` decodes as an empty slice.
    pub fn read_bin(&mut self) -> Result<&'a [u8]> {
        let len = match self.byte()? {
            0xc0 => return Ok(&[]),
            0xc4 => self.be(1)? as usize,
            0xc5 => self.be(2)? as usize,
            0xc6 => self.be(4)? as usize,
            _ => return Err(Error::Msgpack("expected bin")),
        };
        self.take(len)
    }

    /// A `bin` of exactly `N` bytes (Go fixed-size byte arrays).
    pub fn read_bin_exact<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.read_bin()?;
        b.try_into()
            .map_err(|_| Error::Msgpack("fixed-size byte array has wrong length"))
    }

    pub fn read_uint(&mut self) -> Result<u64> {
        match self.byte()? {
            b @ 0x00..=0x7f => Ok(b as u64),
            0xcc => self.be(1),
            0xcd => self.be(2),
            0xce => self.be(4),
            0xcf => self.be(8),
            _ => Err(Error::Msgpack("expected unsigned integer")),
        }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        u8::try_from(self.read_uint()?).map_err(|_| Error::Msgpack("integer overflows u8"))
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        u16::try_from(self.read_uint()?).map_err(|_| Error::Msgpack("integer overflows u16"))
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        match self.byte()? {
            0xc2 => Ok(false),
            0xc3 => Ok(true),
            _ => Err(Error::Msgpack("expected bool")),
        }
    }

    /// Skips one value and returns its raw encoding.
    pub fn raw_value(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        self.skip_depth(0)?;
        Ok(&self.buf[start..self.pos])
    }

    pub fn skip(&mut self) -> Result<()> {
        self.skip_depth(0)
    }

    fn skip_depth(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::Msgpack("nesting too deep"));
        }
        let b = self.byte()?;
        let (skip_bytes, children) = match b {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => (0, 0),
            0x80..=0x8f => (0, 2 * (b & 0x0f) as usize),
            0x90..=0x9f => (0, (b & 0x0f) as usize),
            0xa0..=0xbf => ((b & 0x1f) as usize, 0),
            0xc4 | 0xd9 => (self.be(1)? as usize, 0),
            0xc5 | 0xda => (self.be(2)? as usize, 0),
            0xc6 | 0xdb => (self.be(4)? as usize, 0),
            0xc7 => (self.be(1)? as usize + 1, 0),
            0xc8 => (self.be(2)? as usize + 1, 0),
            0xc9 => (self.be(4)? as usize + 1, 0),
            0xca => (4, 0),
            0xcb => (8, 0),
            0xcc | 0xd0 => (1, 0),
            0xcd | 0xd1 => (2, 0),
            0xce | 0xd2 => (4, 0),
            0xcf | 0xd3 => (8, 0),
            0xd4 => (2, 0),
            0xd5 => (3, 0),
            0xd6 => (5, 0),
            0xd7 => (9, 0),
            0xd8 => (17, 0),
            0xdc => (0, self.be(2)? as usize),
            0xdd => (0, self.be(4)? as usize),
            0xde => (0, 2 * self.be(2)? as usize),
            0xdf => (0, 2 * self.be(4)? as usize),
            0xc1 => return Err(Error::Msgpack("reserved byte 0xc1")),
        };
        self.take(skip_bytes)?;
        for _ in 0..children {
            self.skip_depth(depth + 1)?;
        }
        Ok(())
    }
}

/// Iterates over the fields of a struct-map, rejecting unknown and repeated keys.
///
/// `keys` must list every field the struct may contain; `f` is called with the index of
/// the matched key and the reader positioned at its value.
pub fn read_struct<'a>(
    r: &mut Reader<'a>,
    keys: &[&[u8]],
    mut f: impl FnMut(usize, &mut Reader<'a>) -> Result<()>,
) -> Result<()> {
    let n = r.read_map_len()?;
    let mut seen: u64 = 0;
    debug_assert!(keys.len() <= 64);
    for _ in 0..n {
        let key = r.read_str()?;
        let idx = keys
            .iter()
            .position(|k| *k == key)
            .ok_or(Error::Msgpack("unknown field"))?;
        if seen & (1 << idx) != 0 {
            return Err(Error::Msgpack("duplicate field"));
        }
        seen |= 1 << idx;
        f(idx, r)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Writer (canonical forms only).

pub fn write_map_header(out: &mut Vec<u8>, n: usize) {
    if n < 16 {
        out.push(0x80 | n as u8);
    } else if n <= 0xffff {
        out.push(0xde);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0xdf);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
}

pub fn write_str(out: &mut Vec<u8>, s: &[u8]) {
    let n = s.len();
    if n < 32 {
        out.push(0xa0 | n as u8);
    } else if n <= 0xff {
        out.push(0xd9);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xda);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(s);
}

pub fn write_uint(out: &mut Vec<u8>, v: u64) {
    if v < 0x80 {
        out.push(v as u8);
    } else if v <= 0xff {
        out.push(0xcc);
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(0xcd);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xffff_ffff {
        out.push(0xce);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

pub fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
    let n = b.len();
    if n <= 0xff {
        out.push(0xc4);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xc5);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0xc6);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn uint_roundtrip_uses_shortest_form() {
        for (v, len) in [
            (0u64, 1),
            (127, 1),
            (128, 2),
            (255, 2),
            (256, 3),
            (65535, 3),
            (65536, 5),
            (u32::MAX as u64, 5),
            (u32::MAX as u64 + 1, 9),
        ] {
            let mut out = vec![];
            write_uint(&mut out, v);
            assert_eq!(out.len(), len, "{v}");
            assert_eq!(Reader::new(&out).read_uint().unwrap(), v);
        }
    }

    #[test]
    fn struct_rejects_unknown_and_duplicate_fields() {
        let mut ok = vec![];
        write_map_header(&mut ok, 1);
        write_str(&mut ok, b"a");
        write_uint(&mut ok, 1);
        assert!(read_struct(&mut Reader::new(&ok), &[b"a"], |_, r| r
            .read_uint()
            .map(|_| ()))
        .is_ok());
        assert!(read_struct(&mut Reader::new(&ok), &[b"b"], |_, r| r
            .read_uint()
            .map(|_| ()))
        .is_err());

        let mut dup = vec![];
        write_map_header(&mut dup, 2);
        for _ in 0..2 {
            write_str(&mut dup, b"a");
            write_uint(&mut dup, 1);
        }
        assert!(read_struct(&mut Reader::new(&dup), &[b"a"], |_, r| r
            .read_uint()
            .map(|_| ()))
        .is_err());
    }
}

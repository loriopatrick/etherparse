extern crate byteorder;

use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::ops::Not;

use super::super::*;

use self::byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};


const SERIALIZED_SIZE: usize = 20;
const IPV4_MAX_OPTIONS_LENGTH: usize = 10 * 4;

///A slice containing an ipv4 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4HeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> Ipv4HeaderSlice<&'a [u8]> {
    pub fn from_slice(buffer: &'a [u8]) -> Result<(Ipv4HeaderSlice<&'a [u8]>, &'a [u8]), ReadError> {
        let split = Self::read_length(buffer)?;
        let (header, rest) = buffer.split_at(split);
        Ok((Ipv4HeaderSlice { slice: header }, rest))
    }

    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Ipv4HeaderSlice { slice }
    }
}

impl<'a> Ipv4HeaderSlice<&'a mut [u8]> {
    pub fn from_mut_slice(slice: &'a mut [u8]) -> Result<(Ipv4HeaderSlice<&'a mut [u8]>, &'a mut [u8]), ReadError> {
        let split = Ipv4HeaderSlice::read_length(slice.as_ref())?;
        let (header, rest) = slice.split_at_mut(split);
        Ok((Ipv4HeaderSlice { slice: header }, rest))
    }

    pub fn from_mut_slice_unchecked(slice: &'a mut [u8]) -> Self {
        Ipv4HeaderSlice { slice }
    }
}

impl<T: AsRef<[u8]>> Ipv4HeaderSlice<T> {
    pub fn read_length(buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(SERIALIZED_SIZE));
        }

        //read version & ihl
        let (version, ihl) = {
            let value = slice[0];
            (value >> 4, value & 0xf)
        };

        //check version
        if 4 != version {
            return Err(Ipv4UnexpectedVersion(version));
        }

        //check that the ihl is correct
        if ihl < 5 {
            use crate::ReadError::*;
            return Err(Ipv4HeaderLengthBad(ihl));
        }

        //check that the slice contains enough data for the entire header + options
        let header_length = (usize::from(ihl)) * 4;
        if slice.len() < header_length {
            return Err(UnexpectedEndOfSlice(header_length));
        }

        //check the total_length can contain the header
        let total_length = BigEndian::read_u16(&slice[2..4]);
        if total_length < header_length as u16 {
            return Err(Ipv4TotalLengthTooSmall(total_length));
        }

        Ok(header_length)
    }

    ///Returns the slice containing the ipv4 header
    #[inline]
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Read the "version" field of the IPv4 header (should be 4).
    pub fn version(&self) -> u8 {
        self.slice.as_ref()[0] >> 4
    }

    ///Read the "ip header length" (length of the ipv4 header + options in multiples of 4 bytes).
    pub fn ihl(&self) -> u8 {
        self.slice.as_ref()[0] & 0xf
    }

    ///Read the "differentiated_services_code_point" from the slice.
    pub fn dcp(&self) -> u8 {
        self.slice.as_ref()[1] >> 2
    }

    ///Read the "explicit_congestion_notification" from the slice.
    pub fn ecn(&self) -> u8 {
        self.slice.as_ref()[1] & 0x3
    }

    ///Read the "total length" from the slice (total length of ip header + payload).
    pub fn total_len(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[2..4])
    }

    ///Determine the payload length based on the ihl & total_length field of the header.
    pub fn payload_len(&self) -> u16 {
        self.total_len() - u16::from(self.ihl()) * 4
    }

    ///Read the "identification" field from the slice.
    pub fn identification(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[4..6])
    }

    ///Read the "dont fragment" flag from the slice.
    pub fn dont_fragment(&self) -> bool {
        0 != (self.slice.as_ref()[6] & 0x40)
    }

    ///Read the "more fragments" flag from the slice.
    pub fn more_fragments(&self) -> bool {
        0 != (self.slice.as_ref()[6] & 0x20)
    }

    ///Read the "fragment_offset" field from the slice.
    pub fn fragments_offset(&self) -> u16 {
        let buf = [self.slice.as_ref()[6] & 0x1f, self.slice.as_ref()[7]];
        BigEndian::read_u16(&buf[..])
    }

    ///Read the "time_to_live" field from the slice.
    pub fn ttl(&self) -> u8 {
        self.slice.as_ref()[8]
    }

    ///Read the "protocol" field from the slice.
    pub fn protocol(&self) -> u8 {
        self.slice.as_ref()[9]
    }

    ///Read the "header checksum" field from the slice.
    pub fn header_checksum(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[10..12])
    }

    ///Returns a slice containing the ipv4 source address.
    pub fn source(&self) -> &[u8] {
        &self.slice.as_ref()[12..16]
    }

    ///Return the ipv4 source address as an std::net::Ipv4Addr
    pub fn source_addr(&self) -> Ipv4Addr {
        let mut result: [u8; 4] = Default::default();
        result.copy_from_slice(self.source());
        Ipv4Addr::from(result)
    }

    ///Returns a slice containing the ipv4 source address.
    pub fn destination(&self) -> &[u8] {
        &self.slice.as_ref()[16..20]
    }

    ///Return the ipv4 destination address as an std::net::Ipv4Addr
    pub fn destination_addr(&self) -> Ipv4Addr {
        let mut result: [u8; 4] = Default::default();
        result.copy_from_slice(self.destination());
        Ipv4Addr::from(result)
    }

    ///Returns a slice containing the ipv4 header options (empty when there are no options).
    pub fn options(&self) -> &[u8] {
        &self.slice.as_ref()[20..]
    }

    ///Calculate the header checksum under the assumtion that all value ranges in the header are correct
    pub fn calc_header_checksum_unchecked(&self) -> u16 {
        //version & header_length
        let mut sum: u32 = [
            BigEndian::read_u16(&[(4 << 4) | self.ihl(), (self.dcp() << 2) | self.ecn()]),
            self.total_len(),
            self.identification(),
            //flags & fragmentation offset
            {
                let mut buf: [u8; 2] = [0; 2];
                BigEndian::write_u16(&mut buf, self.fragments_offset());
                let flags = {
                    let mut result = 0;
                    if self.dont_fragment() {
                        result |= 64;
                    }
                    if self.more_fragments() {
                        result |= 32;
                    }
                    result
                };
                BigEndian::read_u16(&[flags | (buf[0] & 0x1f), buf[1]])
            },
            BigEndian::read_u16(&[self.ttl(), self.protocol()]),
            //skip checksum (for obvious reasons)
            BigEndian::read_u16(&self.source()[0..2]),
            BigEndian::read_u16(&self.source()[2..4]),
            BigEndian::read_u16(&self.destination()[0..2]),
            BigEndian::read_u16(&self.destination()[2..4])
        ].iter().map(|x| u32::from(*x)).sum();
        let options = self.options();
        for i in 0..(options.len() / 2) {
            sum += u32::from(BigEndian::read_u16(&options[i * 2..i * 2 + 2]));
        }

        let carry_add = (sum & 0xffff) + (sum >> 16);
        !(((carry_add & 0xffff) + (carry_add >> 16)) as u16)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv4HeaderSlice<T> {
    ///Read the "version" field of the IPv4 header (should be 4).
    pub fn set_version(&mut self, value: u8) {
        let current = self.slice.as_ref()[0];
        self.slice.as_mut()[0] = current & 0b00001111 | (value << 4);
    }

    ///Read the "ip header length" (length of the ipv4 header + options in multiples of 4 bytes).
    pub fn set_ihl(&mut self, value: u8) {
        let current = self.slice.as_ref()[0];
        self.slice.as_mut()[0] = current & 0b11110000 | (value & 0b00001111);
    }

    ///Read the "total length" from the slice (total length of ip header + payload).
    pub fn set_total_len(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[2..4], value)
    }

    ///Read the "identification" field from the slice.
    pub fn set_identification(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[4..6], value)
    }

    ///Read the "dont fragment" flag from the slice.
    pub fn set_dont_fragment(&mut self, set: bool) {
        if set {
            self.slice.as_mut()[6] |= 0x40u8;
        } else {
            self.slice.as_mut()[6] &= 0x40u8.not();
        }
    }

    ///Read the "more fragments" flag from the slice.
    pub fn set_more_fragments(&mut self, set: bool) {
        if set {
            self.slice.as_mut()[6] |= 0x20u8;
        } else {
            self.slice.as_mut()[6] &= 0x20u8.not();
        }
    }

    ///Read the "fragment_offset" field from the slice.
    pub fn set_fragments_offset(&mut self, value: u16) {
        let current = self.slice.as_ref()[6] & 0b11100000;
        BigEndian::write_u16(&mut self.slice.as_mut()[6..8], value);

        let updated = (self.slice.as_ref()[6] & 0b00011111) | current;
        self.slice.as_mut()[6] = updated;
    }

    ///Read the "time_to_live" field from the slice.
    pub fn set_ttl(&mut self, value: u8) {
        self.slice.as_mut()[8] = value;
    }

    ///Read the "protocol" field from the slice.
    pub fn set_protocol(&mut self, value: u8) {
        self.slice.as_mut()[9] = value;
    }

    ///Read the "header checksum" field from the slice.
    pub fn set_header_checksum(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[10..12], value)
    }

    ///Returns a slice containing the ipv4 source address.
    pub fn set_source_address(&mut self, address: Ipv4Addr) {
        self.slice.as_mut()[12..16].copy_from_slice(&address.octets());
    }

    ///Returns a slice containing the ipv4 source address.
    pub fn set_destination_address(&mut self, address: Ipv4Addr) {
        self.slice.as_mut()[16..20].copy_from_slice(&address.octets());
    }

    ///Returns a slice containing the ipv4 header options (empty when there are no options).
    pub fn options_mut(&mut self) -> &mut [u8] {
        &mut self.slice.as_mut()[20..]
    }
}

extern crate byteorder;

use std::net::{Ipv4Addr, Ipv6Addr};

use super::super::*;

use self::byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};

const SERIALIZED_SIZE: usize = 8;

///A slice containing an udp header of a network package. Struct allows the selective read of fields in the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> UdpHeaderSlice<&'a [u8]> {
    pub fn from_slice(slice: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let length = Self::read_length(slice)?;
        let (slice, extra) = slice.split_at(length);
        Ok((UdpHeaderSlice { slice }, extra))
    }

    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        UdpHeaderSlice { slice }
    }
}

impl<'a> UdpHeaderSlice<&'a mut [u8]> {
    pub fn from_mut_slice(slice: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), ReadError> {
        let length = UdpHeaderSlice::read_length(slice.as_ref())?;
        let (slice, extra) = slice.split_at_mut(length);
        Ok((UdpHeaderSlice { slice }, extra))
    }

    pub fn from_mut_slice_unchecked(slice: &'a mut [u8]) -> Self {
        UdpHeaderSlice { slice }
    }
}

impl<T: AsRef<[u8]>> UdpHeaderSlice<T> {
    pub fn read_length(buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(SERIALIZED_SIZE));
        }

        //done
        Ok(SERIALIZED_SIZE)
    }

    ///Returns the slice containing the udp header
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Reads the "udp source port" from the slice.
    pub fn source_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[..2])
    }

    ///Reads the "udp destination port" from the slice.
    pub fn destination_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[2..4])
    }

    ///Reads the "length" from the slice.
    pub fn length(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[4..6])
    }

    ///Reads the "checksum" from the slice.
    pub fn checksum(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[6..8])
    }


    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4<K: AsRef<[u8]>>(&self, ip_header: &Ipv4HeaderSlice<K>, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source_addr(), ip_header.destination_addr(), ip_header.protocol(), payload)
    }

    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4_raw(&self, source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (u16::MAX as usize) - SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv4_internal(source, destination, protocol, payload))
    }

    ///Calculates the upd header checksum based on a ipv4 header.
    fn calc_checksum_ipv4_internal(&self, source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
        self.calc_checksum_post_ip(u64::from(BigEndian::read_u16(&source.octets()[0..2])) + //pseudo header
                                       u64::from(BigEndian::read_u16(&source.octets()[2..4])) +
                                       u64::from(BigEndian::read_u16(&destination.octets()[0..2])) +
                                       u64::from(BigEndian::read_u16(&destination.octets()[2..4])) +
                                       u64::from(protocol) +
                                       u64::from(self.length()),
                                   payload)
    }

    ///Calculates the checksum of the current udp header given an ipv6 header and the payload.
    pub fn calc_checksum_ipv6<K: AsRef<[u8]>>(&self, ip_header: &Ipv6HeaderSlice<K>, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source_addr(), ip_header.destination_addr(), payload)
    }

    ///Calculates the checksum of the current udp header given an ipv6 source & destination address plus the payload.
    pub fn calc_checksum_ipv6_raw(&self, source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv6_internal(source, destination, payload))
    }

    fn calc_checksum_ipv6_internal(&self, source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> u16 {
        fn calc_sum(value: [u8; 16]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i * 2;
                result += u64::from(BigEndian::read_u16(&value[index..(index + 2)]));
            }
            result
        }
        self.calc_checksum_post_ip(calc_sum(source.octets()) +
                                       calc_sum(destination.octets()) +
                                       IpTrafficClass::Udp as u64 +
                                       u64::from(self.length()),
                                   payload)
    }

    ///This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: u64, payload: &[u8]) -> u16 {
        let mut sum = ip_pseudo_header_sum +
            u64::from(self.source_port()) + //udp header start
            u64::from(self.destination_port()) +
            u64::from(self.length());

        for i in 0..(payload.len() / 2) {
            sum += u64::from(BigEndian::read_u16(&payload[i * 2..i * 2 + 2]));
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += u64::from(BigEndian::read_u16(&[*payload.last().unwrap(), 0]));
        }
        let carry_add = (sum & 0xffff) +
            ((sum >> 16) & 0xffff) +
            ((sum >> 32) & 0xffff) +
            ((sum >> 48) & 0xffff);
        let result = ((carry_add & 0xffff) + (carry_add >> 16)) as u16;
        if 0xffff == result {
            result //avoid the transmition of an all 0 checksum as this value is reserved by "checksum disabled" (see rfc)
        } else {
            !result
        }
    }
}

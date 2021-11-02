extern crate byteorder;

use std::net::Ipv6Addr;

use super::super::*;

use self::byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};


const SERIALIZED_SIZE: usize = 40;

///A slice containing an ipv6 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6HeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> Ipv6HeaderSlice<&'a [u8]> {
    pub fn from_slice(slice: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let len = Self::read_length(slice)?;
        let (slice, extra) = slice.split_at(len);
        Ok((Ipv6HeaderSlice { slice }, extra))
    }

    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Ipv6HeaderSlice { slice }
    }
}

impl<'a> Ipv6HeaderSlice<&'a mut [u8]> {
    pub fn from_mut_slice(slice: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), ReadError> {
        let len = Ipv6HeaderSlice::read_length(slice.as_ref())?;
        let (slice, extra) = slice.split_at_mut(len);
        Ok((Ipv6HeaderSlice { slice }, extra))
    }

    pub fn from_mut_slice_unchecked(slice: &'a mut [u8]) -> Self {
        Ipv6HeaderSlice { slice }
    }
}

impl<T: AsRef<[u8]>> Ipv6HeaderSlice<T> {
    ///Creates a slice containing an ipv6 header (without header extensions).
    pub fn read_length(buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(SERIALIZED_SIZE));
        }

        //read version & ihl
        let version = slice[0] >> 4;

        //check version
        if 6 != version {
            return Err(Ipv6UnexpectedVersion(version));
        }

        //all good
        Ok(SERIALIZED_SIZE)
    }

    ///Returns the slice containing the ipv6 header
    #[inline]
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Read the "version" field from the slice (should be 6).
    pub fn version(&self) -> u8 {
        self.slice.as_ref()[0] >> 4
    }

    ///Read the "traffic class" field from the slice.
    pub fn traffic_class(&self) -> u8 {
        (self.slice.as_ref()[0] << 4) | (self.slice.as_ref()[1] >> 4)
    }

    ///Read the "flow label" field from the slice.
    pub fn flow_label(&self) -> u32 {
        byteorder::BigEndian::read_u32(&[0, self.slice.as_ref()[1] & 0xf, self.slice.as_ref()[2], self.slice.as_ref()[3]])
    }

    ///Read the "payload length" field from  the slice. The length should contain the length of all extension headers and payload.
    pub fn payload_length(&self) -> u16 {
        byteorder::BigEndian::read_u16(&self.slice.as_ref()[4..6])
    }

    ///Read the "next header" field from the slice. The next header value specifies what the next header or transport layer protocol is (see IpTrafficClass for a definitions of ids).
    pub fn next_header(&self) -> u8 {
        self.slice.as_ref()[6]
    }

    ///Read the "hop limit" field from the slice. The hop limit specifies the number of hops the packet can take before it is discarded.
    pub fn hop_limit(&self) -> u8 {
        self.slice.as_ref()[7]
    }

    ///Returns a slice containing the IPv6 source address.
    pub fn source(&self) -> &[u8] {
        &self.slice.as_ref()[8..8 + 16]
    }

    ///Return the ipv6 source address as an std::net::Ipv6Addr
    pub fn source_addr(&self) -> Ipv6Addr {
        let mut result: [u8; 16] = Default::default();
        result.copy_from_slice(self.source());
        Ipv6Addr::from(result)
    }

    ///Returns a slice containing the IPv6 destination address.
    pub fn destination(&self) -> &[u8] {
        &self.slice.as_ref()[24..24 + 16]
    }

    ///Return the ipv6 destination address as an std::net::Ipv6Addr
    pub fn destination_addr(&self) -> Ipv6Addr {
        let mut result: [u8; 16] = Default::default();
        result.copy_from_slice(self.destination());
        Ipv6Addr::from(result)
    }
}

///Maximum number of header extensions allowed (according to the ipv6 rfc8200, & iana protocol numbers).
pub const IPV6_MAX_NUM_HEADER_EXTENSIONS: usize = 12;

///Dummy struct for ipv6 header extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6ExtensionHeader {
    next_header: u8,
    length: u8,
}

///A slice containing an ipv6 extension header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6ExtensionHeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> Ipv6ExtensionHeaderSlice<&'a [u8]> {
    ///Creates a slice containing an ipv6 header extension.
    pub fn from_slice(header_type: u8, slice: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let length = Self::read_length(header_type, slice)?;
        let (slice, extra) = slice.split_at(length);
        Ok((Ipv6ExtensionHeaderSlice { slice }, extra))
    }
}

impl<'a> Ipv6ExtensionHeaderSlice<&'a mut [u8]> {
    ///Creates a slice containing an ipv6 header extension.
    pub fn from_slice(header_type: u8, slice: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), ReadError> {
        let length = Ipv6ExtensionHeaderSlice::read_length(header_type, slice.as_ref())?;
        let (slice, extra) = slice.split_at_mut(length);
        Ok((Ipv6ExtensionHeaderSlice { slice }, extra))
    }
}

impl<T: AsRef<[u8]>> Ipv6ExtensionHeaderSlice<T> {
    ///Creates a slice containing an ipv6 header extension.
    pub fn read_length(header_type: u8, buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < 8 {
            return Err(UnexpectedEndOfSlice(8));
        }

        //check length
        const FRAG: u8 = IpTrafficClass::IPv6FragmentationHeader as u8;
        let len = if FRAG == header_type {
            8
        } else {
            ((slice[1] as usize) + 1) * 8
        };

        //check the length again now that the expected length is known
        if slice.len() < len {
            return Err(UnexpectedEndOfSlice(len));
        }

        //all good
        Ok(len)
    }

    ///Returns the slice containing the ipv6 extension header
    #[inline]
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Returns the id of the next header (see IpTrafficClass for a definition of all ids).
    pub fn next_header(&self) -> u8 {
        self.slice.as_ref()[0]
    }
}

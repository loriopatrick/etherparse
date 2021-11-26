extern crate byteorder;

use std::io;

use super::super::*;

use self::byteorder::{BigEndian, ByteOrder, ReadBytesExt};


///Ether type enum present in ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    ProviderBridging = 0x88A8,
    VlanDoubleTaggedFrame = 0x9100,
}

impl EtherType {
    ///Tries to convert a raw ether type value to the enum. Returns None if the value does not exist in the enum.
    pub fn from_u16(value: u16) -> Option<EtherType> {
        use self::EtherType::*;
        match value {
            0x0800 => Some(Ipv4),
            0x86dd => Some(Ipv6),
            0x0806 => Some(Arp),
            0x0842 => Some(WakeOnLan),
            0x88A8 => Some(ProviderBridging),
            0x8100 => Some(VlanTaggedFrame),
            0x9100 => Some(VlanDoubleTaggedFrame),
            _ => None
        }
    }
}

///A slice containing an ethernet 2 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ethernet2HeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> Ethernet2HeaderSlice<&'a [u8]> {
    pub fn from_slice(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let len = Self::read_length(buffer)?;
        let (slice, extra) = buffer.split_at(len);

        Ok((Ethernet2HeaderSlice {
            slice
        }, extra))
    }

    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Ethernet2HeaderSlice {
            slice
        }
    }
}

impl<'a> Ethernet2HeaderSlice<&'a mut [u8]> {
    pub fn from_mut_slice(buffer: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), ReadError> {
        let len = Ethernet2HeaderSlice::read_length(buffer.as_ref())?;
        let (slice, extra) = buffer.split_at_mut(len);

        Ok((Ethernet2HeaderSlice {
            slice
        }, extra))
    }

    pub fn from_mut_slice_unchecked(slice: &'a mut [u8]) -> Self {
        Ethernet2HeaderSlice {
            slice
        }
    }
}

const SERIALIZED_SIZE: usize = 14;

impl<T: AsRef<[u8]>> Ethernet2HeaderSlice<T> {
    pub fn read_length(buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(SERIALIZED_SIZE));
        }

        Ok(14)
    }

    ///Returns the slice containing the ethernet 2 header
    #[inline]
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Read the destination mac address
    pub fn destination(&self) -> &[u8] {
        &self.slice.as_ref()[..6]
    }

    ///Read the source mac address
    pub fn source(&self) -> &[u8] {
        &self.slice.as_ref()[6..12]
    }

    ///Read the ether_type field of the header (in system native byte order).
    pub fn ether_type(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[12..14])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ethernet2HeaderSlice<T> {
    ///Read the destination mac address
    pub fn set_destination(&mut self, address: &[u8]) {
        self.slice.as_mut()[..6].copy_from_slice(address);
    }

    ///Read the destination mac address
    pub fn destination_mut(&mut self) -> &mut [u8] {
        &mut self.slice.as_mut()[..6]
    }

    ///Read the source mac address
    pub fn set_source(&mut self, address: &[u8]) {
        self.slice.as_mut()[6..12].copy_from_slice(address)
    }

    ///Read the source mac address
    pub fn source_mut(&mut self) -> &mut [u8] {
        &mut self.slice.as_mut()[6..12]
    }

    ///Read the ether_type field of the header (in system native byte order).
    pub fn set_ether_type(&mut self, ether_type: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[12..14], ether_type)
    }
}
use super::super::*;

extern crate byteorder;

use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt};

use std::io;

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

///Ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ethernet2Header {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ether_type: u16,
}

impl SerializedSize for Ethernet2Header {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 14;
}

impl Ethernet2Header {
    ///Reads an Ethernet-II header from the current position of the read argument.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ethernet2Header, io::Error> {
        fn read_mac_address<T: io::Read>(read: &mut T) -> Result<[u8; 6], io::Error> {
            let mut result: [u8; 6] = [0; 6];
            read.read_exact(&mut result)?;
            Ok(result)
        }

        Ok(Ethernet2Header {
            destination: read_mac_address(reader)?,
            source: read_mac_address(reader)?,
            ether_type: reader.read_u16::<BigEndian>()?,
        })
    }

    ///Serialize the header to a given slice. Returns the unused part of the slice.
    pub fn write_to_slice<'a>(&self, slice: &'a mut [u8]) -> Result<&'a mut [u8], WriteError> {
        use self::WriteError::*;
        //length check
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            Err(SliceTooSmall(Ethernet2Header::SERIALIZED_SIZE))
        } else {
            self.write_to_slice_unchecked(slice);
            Ok(&mut slice[Ethernet2Header::SERIALIZED_SIZE..])
        }
    }

    ///Writes a given Ethernet-II header to the current position of the write argument.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), io::Error> {
        let mut buffer: [u8; Ethernet2Header::SERIALIZED_SIZE] = Default::default();
        self.write_to_slice_unchecked(&mut buffer);
        writer.write_all(&buffer)
    }

    ///Write the header to a slice without checking the slice length
    fn write_to_slice_unchecked(&self, slice: &mut [u8]) {
        slice[..6].copy_from_slice(&self.destination);
        slice[6..12].copy_from_slice(&self.source);
        BigEndian::write_u16(&mut slice[12..14], self.ether_type);
    }
}

///A slice containing an ethernet 2 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ethernet2HeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> Ethernet2HeaderSlice<&'a [u8]> {
    ///Creates a ethernet slice from an other slice.
    pub fn from_slice(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let len = Self::length(buffer)?;
        let (slice, extra) = buffer.split_at(len);

        Ok((Ethernet2HeaderSlice {
            slice
        }, extra))
    }
}

impl<T: AsRef<[u8]>> Ethernet2HeaderSlice<T> {
    pub fn length(buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Ethernet2Header::SERIALIZED_SIZE));
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

    ///Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> Ethernet2Header {
        Ethernet2Header {
            source: {
                let mut result: [u8; 6] = Default::default();
                result.copy_from_slice(self.source());
                result
            },
            destination: {
                let mut result: [u8; 6] = Default::default();
                result.copy_from_slice(self.destination());
                result
            },
            ether_type: self.ether_type(),
        }
    }
}
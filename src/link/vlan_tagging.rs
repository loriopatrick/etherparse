use super::super::*;

extern crate byteorder;

use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;
use std::io::Read;

///IEEE 802.1Q VLAN Tagging Header (can be single or double tagged).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanHeader {
    ///IEEE 802.1Q VLAN Tagging Header
    Single(SingleVlanHeader),
    ///IEEE 802.1Q double VLAN Tagging Header
    Double(DoubleVlanHeader),
}

///IEEE 802.1Q VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SingleVlanHeader {
    ///A 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub priority_code_point: u8,
    ///Indicate that the frame may be dropped under the presence of congestion.
    pub drop_eligible_indicator: bool,
    ///12 bits vland identifier.
    pub vlan_identifier: u16,
    ///"Tag protocol identifier": Type id of content after this header. Refer to the "EtherType" for a list of possible supported values.
    pub ether_type: u16,
}

impl SerializedSize for SingleVlanHeader {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 4;
}

impl SingleVlanHeader {
    ///Read a IEEE 802.1Q VLAN tagging header
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<SingleVlanHeader, io::Error> {
        let (priority_code_point, drop_eligible_indicator, vlan_identifier) = {
            let mut buffer: [u8; 2] = [0; 2];
            reader.read_exact(&mut buffer)?;
            let drop_eligible_indicator = 0 != (buffer[0] & 0x10);
            let priority_code_point = buffer[0] >> 5;
            //mask and read the vlan id
            buffer[0] &= 0xf;
            (priority_code_point, drop_eligible_indicator, BigEndian::read_u16(&buffer))
        };

        Ok(SingleVlanHeader {
            priority_code_point,
            drop_eligible_indicator,
            vlan_identifier,
            ether_type: reader.read_u16::<BigEndian>()?,
        })
    }

    ///Write the IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::ErrorField::*;
        //check value ranges
        max_check_u8(self.priority_code_point, 0x7, VlanTagPriorityCodePoint)?;
        max_check_u16(self.vlan_identifier, 0xfff, VlanTagVlanId)?;
        {
            let mut buffer: [u8; 2] = [0; 2];
            BigEndian::write_u16(&mut buffer, self.vlan_identifier);
            if self.drop_eligible_indicator {
                buffer[0] |= 0x10;
            }
            buffer[0] |= self.priority_code_point << 5;
            writer.write_all(&buffer)?;
        }
        writer.write_u16::<BigEndian>(self.ether_type)?;
        Ok(())
    }
}

///IEEE 802.1Q double VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVlanHeader {
    ///The outer vlan tagging header
    pub outer: SingleVlanHeader,
    ///The inner vlan tagging header
    pub inner: SingleVlanHeader,
}

impl SerializedSize for DoubleVlanHeader {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 8;
}

impl DoubleVlanHeader {
    ///Read an DoubleVlanHeader from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(DoubleVlanHeader, &[u8]), ReadError> {
        Ok((
            DoubleVlanHeaderSlice::from_slice(slice)?.to_header(),
            &slice[DoubleVlanHeader::SERIALIZED_SIZE..]
        ))
    }

    ///Read a double tagging header from the given source
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<DoubleVlanHeader, ReadError> {
        let outer = SingleVlanHeader::read(reader)?;


        use crate::EtherType::*;
        const VLAN_TAGGED_FRAME: u16 = VlanTaggedFrame as u16;
        const PROVIDER_BRIDGING: u16 = ProviderBridging as u16;
        const VLAN_DOUBLE_TAGGED_FRAME: u16 = VlanDoubleTaggedFrame as u16;

        //check that outer ethertype is matching
        match outer.ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                Ok(DoubleVlanHeader {
                    outer,
                    inner: SingleVlanHeader::read(reader)?,
                })
            }
            value => {
                use crate::ReadError::*;
                Err(VlanDoubleTaggingUnexpectedOuterTpid(value))
            }
        }
    }

    ///Write the double IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        self.outer.write(writer)?;
        self.inner.write(writer)
    }
}

///A slice containing a single vlan header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleVlanHeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> SingleVlanHeaderSlice<&'a [u8]> {
    pub fn from_slice(slice: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let length = Self::length(slice)?;
        let (slice, extra) = slice.split_at(length);

        Ok((SingleVlanHeaderSlice { slice }, extra))
    }
}

impl<'a> SingleVlanHeaderSlice<&'a mut [u8]> {
    pub fn from_slice(slice: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), ReadError> {
        let length = Self::length(slice)?;
        let (slice, extra) = slice.split_at_mut(length);

        Ok((SingleVlanHeaderSlice { slice }, extra))
    }
}

impl<T: AsRef<[u8]>> SingleVlanHeaderSlice<T> {
    pub fn length(buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < SingleVlanHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(SingleVlanHeader::SERIALIZED_SIZE));
        }

        //all done
        Ok(SingleVlanHeader::SERIALIZED_SIZE)
    }

    ///Returns the slice containing the single vlan header
    #[inline]
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Read the "priority_code_point" field from the slice. This is a 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub fn priority_code_point(&self) -> u8 {
        self.slice.as_ref()[0] >> 5
    }

    ///Read the "drop_eligible_indicator" flag from the slice. Indicates that the frame may be dropped under the presence of congestion.
    pub fn drop_eligible_indicator(&self) -> bool {
        0 != (self.slice.as_ref()[0] & 0x10)
    }

    ///Reads the 12 bits "vland identifier" field from the slice.
    pub fn vlan_identifier(&self) -> u16 {
        let buffer = [self.slice.as_ref()[0] & 0xf, self.slice.as_ref()[1]];
        BigEndian::read_u16(&buffer)
    }

    ///Read the "Tag protocol identifier" field from the slice. Refer to the "EtherType" for a list of possible supported values.
    pub fn ether_type(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[2..4])
    }

    ///Decode all the fields and copy the results to a SingleVlanHeader struct
    pub fn to_header(&self) -> SingleVlanHeader {
        SingleVlanHeader {
            priority_code_point: self.priority_code_point(),
            drop_eligible_indicator: self.drop_eligible_indicator(),
            vlan_identifier: self.vlan_identifier(),
            ether_type: self.ether_type(),
        }
    }
}

///A slice containing an double vlan header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVlanHeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<T: AsRef<[u8]>> DoubleVlanHeaderSlice<T> {
    ///Creates a double header slice from a slice.
    pub fn from_slice(buffer: T) -> Result<Self, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < DoubleVlanHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(DoubleVlanHeader::SERIALIZED_SIZE));
        }

        //create slice
        let result = DoubleVlanHeaderSlice {
            slice: &slice[..DoubleVlanHeader::SERIALIZED_SIZE]
        };

        use crate::EtherType::*;
        const VLAN_TAGGED_FRAME: u16 = VlanTaggedFrame as u16;
        const PROVIDER_BRIDGING: u16 = ProviderBridging as u16;
        const VLAN_DOUBLE_TAGGED_FRAME: u16 = VlanDoubleTaggedFrame as u16;

        //check that outer ethertype is matching
        match result.outer().ether_type() {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                //all done
                Ok(result)
            }
            value => {
                Err(VlanDoubleTaggingUnexpectedOuterTpid(value))
            }
        }
    }

    ///Returns the slice containing the double vlan header
    #[inline]
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Returns a slice with the outer vlan header
    pub fn outer(&self) -> SingleVlanHeaderSlice<&[u8]> {
        SingleVlanHeaderSlice {
            slice: &self.slice.as_ref()[..SingleVlanHeader::SERIALIZED_SIZE]
        }
    }

    ///Returns a slice with the inner vlan header.
    pub fn inner(&self) -> SingleVlanHeaderSlice<&[u8]> {
        SingleVlanHeaderSlice {
            slice: &self.slice.as_ref()[SingleVlanHeader::SERIALIZED_SIZE..SingleVlanHeader::SERIALIZED_SIZE * 2]
        }
    }

    ///Decode all the fields and copy the results to a DoubleVlanHeader struct
    pub fn to_header(&self) -> DoubleVlanHeader {
        DoubleVlanHeader {
            outer: self.outer().to_header(),
            inner: self.inner().to_header(),
        }
    }
}
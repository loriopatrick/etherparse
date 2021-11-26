extern crate byteorder;

use std::fmt::{Debug, Formatter};

use super::super::*;

use self::byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};

///The minimum size of the tcp header in bytes
pub const TCP_MINIMUM_HEADER_SIZE: usize = 5 * 4;
///The minimum data offset size (size of the tcp header itself).
pub const TCP_MINIMUM_DATA_OFFSET: u8 = 5;
///The maximum allowed value for the data offset (it is a 4 bit value).
pub const TCP_MAXIMUM_DATA_OFFSET: u8 = 0xf;

///A slice containing an tcp header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeaderSlice<T: AsRef<[u8]>> {
    slice: T,
}

impl<'a> TcpHeaderSlice<&'a [u8]> {
    ///Creates a slice containing an tcp header.
    pub fn from_slice(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let len = TcpHeaderSlice::read_length(buffer)?;
        let (slice, extra) = buffer.split_at(len);
        Ok((TcpHeaderSlice { slice }, extra))
    }

    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        TcpHeaderSlice { slice }
    }
}

impl<'a> TcpHeaderSlice<&'a mut [u8]> {
    ///Creates a slice containing an tcp header.
    pub fn from_mut_slice(buffer: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), ReadError> {
        let len = TcpHeaderSlice::read_length(buffer.as_ref())?;
        let (slice, extra) = buffer.split_at_mut(len);
        Ok((TcpHeaderSlice { slice }, extra))
    }

    pub fn from_mut_slice_unchecked(slice: &'a mut [u8]) -> Self {
        TcpHeaderSlice { slice }
    }
}

impl<T: AsRef<[u8]>> TcpHeaderSlice<T> {
    pub fn read_length(buffer: T) -> Result<usize, ReadError> {
        let slice = buffer.as_ref();

        //check length
        use crate::ReadError::*;
        if slice.len() < TCP_MINIMUM_HEADER_SIZE {
            return Err(UnexpectedEndOfSlice(TCP_MINIMUM_HEADER_SIZE));
        }

        //read data offset
        let data_offset = (slice[12] & 0xf0) >> 4;
        let len = data_offset as usize * 4;

        if data_offset < TCP_MINIMUM_DATA_OFFSET {
            Err(ReadError::TcpDataOffsetTooSmall(data_offset))
        } else if slice.len() < len {
            Err(UnexpectedEndOfSlice(len))
        } else {
            //done
            Ok(len)
        }
    }

    ///Returns the slice containing the tcp header
    pub fn slice(&self) -> &[u8] {
        self.slice.as_ref()
    }

    ///Read the destination port number.
    pub fn source_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[..2])
    }

    ///Read the destination port number.
    pub fn destination_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[2..4])
    }

    ///Read the sequence number of the first data octet in this segment (except when SYN is present).
    ///
    ///If SYN is present the sequence number is the initial sequence number (ISN) 
    ///and the first data octet is ISN+1.
    ///[copied from RFC 793, page 16]
    pub fn sequence_number(&self) -> u32 {
        BigEndian::read_u32(&self.slice.as_ref()[4..8])
    }

    ///Reads the acknowledgment number.
    ///
    ///If the ACK control bit is set this field contains the value of the
    ///next sequence number the sender of the segment is expecting to
    ///receive.
    ///
    ///Once a connection is established this is always sent.
    pub fn acknowledgment_number(&self) -> u32 {
        BigEndian::read_u32(&self.slice.as_ref()[8..12])
    }

    ///Read the number of 32 bit words in the TCP Header.
    ///
    ///This indicates where the data begins.  The TCP header (even one including options) is an
    ///integral number of 32 bits long.
    pub fn data_offset(&self) -> u8 {
        (self.slice.as_ref()[12] & 0xf0) >> 4
    }

    pub fn flags(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[12..14]) & 0x01FF
    }

    ///ECN-nonce - concealment protection (experimental: see RFC 3540)
    pub fn ns(&self) -> bool {
        0 != (self.slice.as_ref()[12] & 1)
    }

    ///Read the fin flag (no more data from sender).
    pub fn fin(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 1)
    }

    ///Reads the syn flag (synchronize sequence numbers).
    pub fn syn(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 2)
    }

    ///Reads the rst flag (reset the connection).
    pub fn rst(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 4)
    }

    ///Reads the psh flag (push function).
    pub fn psh(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 8)
    }

    ///Reads the ack flag (acknowledgment field significant).
    pub fn ack(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 16)
    }

    ///Reads the urg flag (Urgent Pointer field significant).
    pub fn urg(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 32)
    }

    ///Read the ECN-Echo flag (RFC 3168).
    pub fn ece(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 64)
    }

    ///Reads the cwr flag (Congestion Window Reduced). 
    ///
    ///This flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
    pub fn cwr(&self) -> bool {
        0 != (self.slice.as_ref()[13] & 128)
    }

    ///The number of data octets beginning with the one indicated in the
    ///acknowledgment field which the sender of this segment is willing to
    ///accept.
    pub fn window_size(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[14..16])
    }

    ///Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    pub fn checksum(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[16..18])
    }

    ///This field communicates the current value of the urgent pointer as a
    ///positive offset from the sequence number in this segment.
    ///
    ///The urgent pointer points to the sequence number of the octet following
    ///the urgent data.  This field is only be interpreted in segments with
    ///the URG control bit set.
    pub fn urgent_pointer(&self) -> u16 {
        BigEndian::read_u16(&self.slice.as_ref()[18..20])
    }

    ///Options of the header
    pub fn options(&self) -> &[u8] {
        &self.slice.as_ref()[TCP_MINIMUM_HEADER_SIZE..self.data_offset() as usize * 4]
    }

    ///Returns an iterator that allows to iterate through all known TCP header options.
    pub fn options_iterator(&self) -> TcpOptionsIterator {
        TcpOptionsIterator::from_slice(self.options())
    }

    ///Calculates the upd header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4<K: AsRef<[u8]>>(&self, ip_header: &Ipv4HeaderSlice<K>, payload: &[u8]) -> Result<u16, ValueError> {
        let tcp_len = ip_header.total_len() as usize - (payload.len() + ip_header.ihl() as usize * 4);
        self.calc_checksum_ipv4_raw(ip_header.source(), ip_header.destination(), tcp_len, payload)
    }

    ///Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    fn calc_checksum_ipv4_raw(&self, source_ip: &[u8], destination_ip: &[u8], tcp_len: usize, payload: &[u8]) -> Result<u16, ValueError> {

        //check that the total length fits into the field
        let tcp_length = tcp_len + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        //calculate the checksum
        Ok(Self::calc_checksum_post_ip(u64::from(BigEndian::read_u16(&source_ip[0..2])) + //pseudo header
                                           u64::from(BigEndian::read_u16(&source_ip[2..4])) +
                                           u64::from(BigEndian::read_u16(&destination_ip[0..2])) +
                                           u64::from(BigEndian::read_u16(&destination_ip[2..4])) +
                                           IpTrafficClass::Tcp as u64 +
                                           tcp_length as u64,
                                       &self.slice()[..tcp_len],
                                       payload))
    }

    ///Calculates the upd header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6<K: AsRef<[u8]>>(&self, ip_header: Ipv6HeaderSlice<K>, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(&ip_header.source(), &ip_header.destination(), payload)
    }

    ///Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(&self, source: &[u8], destination: &[u8], payload: &[u8]) -> Result<u16, ValueError> {

        //check that the total length fits into the field
        let tcp_length = (self.data_offset() as usize) * 4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        fn calc_addr_sum(value: &[u8]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i * 2;
                result += u64::from(BigEndian::read_u16(&value[index..(index + 2)]));
            }
            result
        }
        Ok(Self::calc_checksum_post_ip(
            calc_addr_sum(source) +
                calc_addr_sum(destination) +
                IpTrafficClass::Tcp as u64 +
                {
                    let mut buffer: [u8; 4] = Default::default();
                    BigEndian::write_u32(&mut buffer[..], tcp_length as u32);
                    u64::from(BigEndian::read_u16(&buffer[0..2])) +
                        u64::from(BigEndian::read_u16(&buffer[2..4]))
                },
            self.slice(),
            payload))
    }

    ///This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(ip_pseudo_header_sum: u64, tcp_slice: &[u8], payload: &[u8]) -> u16 {
        let mut sum = ip_pseudo_header_sum;

        //until checksum
        for i in RangeStep::new(0, 16, 2) {
            sum += u64::from(BigEndian::read_u16(&tcp_slice[i..i + 2]));
        }
        //after checksum
        for i in RangeStep::new(18, tcp_slice.len(), 2) {
            sum += u64::from(BigEndian::read_u16(&tcp_slice[i..i + 2]));
        }
        //payload
        for i in RangeStep::new(0, payload.len() / 2 * 2, 2) {
            sum += u64::from(BigEndian::read_u16(&payload[i..i + 2]));
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
        !result
    }
}


impl<T: AsRef<[u8]> + AsMut<[u8]>> TcpHeaderSlice<T> {
    ///Read the destination port number.
    pub fn set_source_port(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[..2], value)
    }

    ///Read the destination port number.
    pub fn set_destination_port(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[2..4], value)
    }

    ///Read the sequence number of the first data octet in this segment (except when SYN is present).
    ///
    ///If SYN is present the sequence number is the initial sequence number (ISN)
    ///and the first data octet is ISN+1.
    ///[copied from RFC 793, page 16]
    pub fn set_sequence_number(&mut self, value: u32) {
        BigEndian::write_u32(&mut self.slice.as_mut()[4..8], value)
    }

    ///Reads the acknowledgment number.
    ///
    ///If the ACK control bit is set this field contains the value of the
    ///next sequence number the sender of the segment is expecting to
    ///receive.
    ///
    ///Once a connection is established this is always sent.
    pub fn set_acknowledgment_number(&mut self, value: u32) {
        BigEndian::write_u32(&mut self.slice.as_mut()[8..12], value)
    }

    ///Read the number of 32 bit words in the TCP Header.
    ///
    ///This indicates where the data begins.  The TCP header (even one including options) is an
    ///integral number of 32 bits long.
    pub fn set_data_offset(&mut self, value: u8) {
        let current = self.slice.as_ref()[12] & 0b00001111;
        self.slice.as_mut()[12] = current | (value << 4);
    }

    pub fn set_flags(&mut self, flags: u16) {
        let current = self.slice.as_ref()[12] & 0b11111110;
        self.slice.as_mut()[12] = current | ((flags >> 8) & 1) as u8;
        self.slice.as_mut()[13] = flags as u8;
    }

    ///The number of data octets beginning with the one indicated in the
    ///acknowledgment field which the sender of this segment is willing to
    ///accept.
    pub fn set_window_size(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[14..16], value)
    }

    ///Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    pub fn set_checksum(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[16..18], value)
    }

    ///This field communicates the current value of the urgent pointer as a
    ///positive offset from the sequence number in this segment.
    ///
    ///The urgent pointer points to the sequence number of the octet following
    ///the urgent data.  This field is only be interpreted in segments with
    ///the URG control bit set.
    pub fn set_urgent_pointer(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.slice.as_mut()[18..20], value)
    }

    ///Options of the header
    pub fn set_options_raw(&mut self, value: &[u8]) -> Result<(), ReadError> {
        /* round up */
        let length_words = (value.len() + 3) / 4;

        if TCP_MAXIMUM_DATA_OFFSET as usize - 5 < length_words {
            return Err(ReadError::UnexpectedEndOfSlice(0));
        }

        let new_data_offset_words = length_words + TCP_MINIMUM_DATA_OFFSET as usize;
        if self.slice.as_ref().len() < new_data_offset_words * 4 {
            return Err(ReadError::UnexpectedEndOfSlice(self.slice.as_ref().len()));
        }

        self.set_data_offset(new_data_offset_words as u8);
        let header_len = TCP_MINIMUM_HEADER_SIZE + value.len();
        self.slice.as_mut()[TCP_MINIMUM_HEADER_SIZE..header_len].copy_from_slice(value);

        Ok(())
    }

    pub fn options_mut(&mut self) -> &mut [u8] {
        let range = TCP_MINIMUM_HEADER_SIZE..self.data_offset() as usize * 4;
        &mut self.slice.as_mut()[range]
    }
}

///Different kinds of options that can be present in the options part of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionElement {
    Nop,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SelectiveAcknowledgementPermitted,
    SelectiveAcknowledgement((u32, u32), [Option<(u32, u32)>; 3]),
    ///Timestamp & echo (first number is the sender timestamp, the second the echo timestamp)
    Timestamp(u32, u32),
}

///Errors that can occour while reading the options of a TCP header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionReadError {
    ///Returned if an option id was read, but there was not enough memory in the options left to completely read it.
    UnexpectedEndOfSlice(u8),

    ///Returned if the option as an unexpected size argument (e.g. != 4 for maximum segment size).
    UnexpectedSize { option_id: u8, size: u8 },

    ///Returned if an unknown tcp header option is encountered.
    ///
    ///The first element is the identifier and the slice contains the rest of data left in the options.
    UnknownId(u8),
}

///Errors that can occour when setting the options of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionWriteError {
    ///There is not enough memory to store all options in the options section of the header (maximum 40 bytes).
    ///
    ///The options size is limited by the 4 bit data_offset field in the header which describes
    ///the total tcp header size in multiple of 4 bytes. This leads to a maximum size for the options
    ///part of the header of 4*(15 - 5) (minus 5 for the size of the tcp header itself). 
    NotEnoughSpace(usize)
}

///Allows iterating over the options after a TCP header.
pub struct TcpOptionsIterator<'a> {
    options: &'a [u8],
}

pub const TCP_OPTION_ID_END: u8 = 0;
pub const TCP_OPTION_ID_NOP: u8 = 1;
pub const TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE: u8 = 2;
pub const TCP_OPTION_ID_WINDOW_SCALE: u8 = 3;
pub const TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED: u8 = 4;
pub const TCP_OPTION_ID_SELECTIVE_ACK: u8 = 5;
pub const TCP_OPTION_ID_TIMESTAMP: u8 = 8;

impl<'a> TcpOptionsIterator<'a> {
    ///Creates an options iterator from a slice containing encoded tcp options.
    pub fn from_slice(options: &'a [u8]) -> TcpOptionsIterator<'a> {
        TcpOptionsIterator { options }
    }

    ///Returns the non processed part of the options slice.
    pub fn rest(&self) -> &'a [u8] {
        self.options
    }
}

impl<'a> Iterator for TcpOptionsIterator<'a> {
    type Item = Result<TcpOptionElement, TcpOptionReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        use crate::TcpOptionReadError::*;
        use crate::TcpOptionElement::*;

        let expect_specific_size = |expected_size: u8, slice: &[u8]| -> Result<(), TcpOptionReadError> {
            let id = slice[0];
            if slice.len() < expected_size as usize {
                Err(UnexpectedEndOfSlice(id))
            } else if slice[1] != expected_size {
                Err(UnexpectedSize {
                    option_id: slice[0],
                    size: slice[1],
                })
            } else {
                Ok(())
            }
        };

        if self.options.is_empty() {
            None
        } else {
            //first determine the result
            let result = match self.options[0] {
                //end
                TCP_OPTION_ID_END => {
                    None
                }
                TCP_OPTION_ID_NOP => {
                    self.options = &self.options[1..];
                    Some(Ok(Nop))
                }
                TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE => {
                    match expect_specific_size(4, self.options) {
                        Err(value) => {
                            Some(Err(value))
                        }
                        _ => {
                            let value = BigEndian::read_u16(&self.options[2..4]);
                            self.options = &self.options[4..];
                            Some(Ok(MaximumSegmentSize(value)))
                        }
                    }
                }
                TCP_OPTION_ID_WINDOW_SCALE => {
                    match expect_specific_size(3, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            let value = self.options[2];
                            self.options = &self.options[3..];
                            Some(Ok(WindowScale(value)))
                        }
                    }
                }
                TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED => {
                    match expect_specific_size(2, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            self.options = &self.options[2..];
                            Some(Ok(SelectiveAcknowledgementPermitted))
                        }
                    }
                }
                TCP_OPTION_ID_SELECTIVE_ACK => {
                    //check that the length field can be read
                    if self.options.len() < 2 {
                        Some(Err(UnexpectedEndOfSlice(self.options[0])))
                    } else {
                        //check that the length is an allowed one for this option
                        let len = self.options[1];
                        if len != 10 && len != 18 && len != 26 && len != 34 {
                            Some(Err(UnexpectedSize {
                                option_id: self.options[0],
                                size: len,
                            }))
                        } else if self.options.len() < (len as usize) {
                            Some(Err(UnexpectedEndOfSlice(self.options[0])))
                        } else {
                            let mut acks: [Option<(u32, u32)>; 3] = [None; 3];
                            let first = (BigEndian::read_u32(&self.options[2..2 + 4]),
                                         BigEndian::read_u32(&self.options[2 + 4..2 + 8]));
                            for (i, item) in acks.iter_mut()
                                .enumerate()
                                .take(3)
                            {
                                let offset = 2 + 8 + (i * 8);
                                if offset < (len as usize) {
                                    *item = Some((
                                        BigEndian::read_u32(&self.options[offset..offset + 4]),
                                        BigEndian::read_u32(&self.options[offset + 4..offset + 8]))
                                    );
                                }
                            }
                            //iterate the options
                            self.options = &self.options[len as usize..];
                            Some(Ok(SelectiveAcknowledgement(first, acks)))
                        }
                    }
                }
                TCP_OPTION_ID_TIMESTAMP => {
                    match expect_specific_size(10, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            let t = Timestamp(
                                BigEndian::read_u32(&self.options[2..6]),
                                BigEndian::read_u32(&self.options[6..10]),
                            );
                            self.options = &self.options[10..];
                            Some(Ok(t))
                        }
                    }
                }

                //unknown id
                _ => {
                    Some(Err(UnknownId(self.options[0])))
                }
            };

            //in case the result was an error or the end move the slice to an end position
            match result {
                None | Some(Err(_)) => {
                    let len = self.options.len();
                    self.options = &self.options[len..len];
                }
                _ => {}
            }

            //finally return the result
            result
        }
    }
}

pub mod tcp_flags {
    pub const FIN: u16 = 0b0_0000_0001;
    pub const SYN: u16 = 0b0_0000_0010;
    pub const RST: u16 = 0b0_0000_0100;
    pub const PSH: u16 = 0b0_0000_1000;
    pub const ACK: u16 = 0b0_0001_0000;
    pub const URG: u16 = 0b0_0010_0000;
    pub const ECE: u16 = 0b0_0100_0000;
    pub const CWR: u16 = 0b0_1000_0000;
    pub const NS: u16 = 0b1_0000_0000;
}
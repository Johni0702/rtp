// FIXME: saveguard against two-time pad by running replay-protection on outgoing packets
use fixedbitset::FixedBitSet;
use handy_async::sync_io::{ReadExt, WriteExt};
use num::{BigUint, Integer};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use trackable::*;

use crate::io::{ReadFrom, WriteTo};
use crate::rfc3550;
use crate::traits::{ReadPacket, RtcpPacket, RtpPacket, WritePacket};
use crate::types::{Ssrc, U48};
use crate::{ErrorKind, Result};
use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
use hmac::{Mac, NewMac};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AesCm,
    AesF8,
    Null,
}
impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        EncryptionAlgorithm::AesCm
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationAlgorithm {
    HmacSha1,
}
impl Default for AuthenticationAlgorithm {
    fn default() -> Self {
        AuthenticationAlgorithm::HmacSha1
    }
}

pub trait Protocol: Sized + Default {
    type PacketIndex: Sized + Ord + Into<u64> + Into<BigUint> + Copy;
    const ENC_KEY_LABEL: u8;
    const AUTH_KEY_LABEL: u8;
    const SALT_KEY_LABEL: u8;

    fn read_ssrc(packet: &[u8]) -> Result<Ssrc>;
    fn determine_incoming_packet_index(
        context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
    ) -> Result<Self::PacketIndex>;
    fn determine_outgoing_packet_index(
        context: &SsrcContext<Self>,
        packet: &[u8],
    ) -> Result<Self::PacketIndex>;
    fn get_authenticated_bytes<'a>(
        context: &Context<Self>,
        index: Self::PacketIndex,
        auth_portion: &'a [u8],
    ) -> Result<Cow<'a, [u8]>>;
    fn decrypt(
        context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>>;
    fn encrypt(
        context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>>;
    fn update_highest_recv_index(context: &mut SsrcContext<Self>, index: Self::PacketIndex);
    fn update_highest_sent_index(context: &mut SsrcContext<Self>, index: Self::PacketIndex);
}

// TODO maybe use type marker to ensure one context is only ever used for either sending OR receiving
// https://tools.ietf.org/html/rfc3711#section-3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context<P: Protocol> {
    // TODO support re-keying
    // TODO support mki
    pub master_key: Vec<u8>,
    pub master_salt: Vec<u8>,
    // Since actual kdr is a power of two, this only stores the power (+1).
    // i.e. actual kdr is 2^(key_derivation_rate-1) (or 0 in case of 0)
    pub key_derivation_rate: u8,
    pub encryption: EncryptionAlgorithm,
    pub authentication: AuthenticationAlgorithm,
    pub auth_tag_len: usize,
    pub unknown_ssrcs: usize,
    pub ssrc_context: BTreeMap<u32, SsrcContext<P>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrcContext<P: Protocol> {
    pub replay_window_head: u64,
    pub replay_window: FixedBitSet,
    pub session_encr_key: Vec<u8>,
    pub session_salt_key: Vec<u8>,
    pub session_auth_key: Vec<u8>,
    pub protocol_specific: P,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srtp {
    pub rollover_counter: u32,
    pub highest_seq_num: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srtcp {
    pub highest_sent_index: u32, // actually only 31-bits
}

impl Default for Srtp {
    fn default() -> Self {
        Srtp {
            rollover_counter: 0,
            highest_seq_num: 0,
        }
    }
}

impl Default for Srtcp {
    fn default() -> Self {
        Srtcp {
            highest_sent_index: 0,
        }
    }
}

impl Srtp {
    fn parse_seq_num(packet: &[u8]) -> Result<u16> {
        let reader = &mut &packet[..];
        let header = track_try!(rfc3550::RtpFixedHeader::read_from(reader));
        Ok(header.seq_num)
    }

    // Estimate packet index from packet sequence number, highest received
    // sequence number and current rollover_counter, i.e. determining the most
    // likely (minimizing index offset) ROC for the given sequence number.
    // As per https://tools.ietf.org/html/rfc3711#section-3.3.1
    fn estimate_packet_index(context: &Self, seq_num: u16) -> U48 {
        let Srtp {
            highest_seq_num,
            rollover_counter,
        } = context;
        let mid_seq_num = 1 << 15;
        let probable_roc = if *highest_seq_num < mid_seq_num {
            if highest_seq_num + mid_seq_num < seq_num {
                rollover_counter.wrapping_sub(1)
            } else {
                *rollover_counter
            }
        } else {
            if highest_seq_num - mid_seq_num > seq_num {
                rollover_counter.wrapping_add(1)
            } else {
                *rollover_counter
            }
        };
        (U48::from(probable_roc) << 16) + U48::from(seq_num)
    }
}

impl Protocol for Srtp {
    type PacketIndex = U48;
    const ENC_KEY_LABEL: u8 = 0;
    const AUTH_KEY_LABEL: u8 = 1;
    const SALT_KEY_LABEL: u8 = 2;

    fn read_ssrc(packet: &[u8]) -> Result<Ssrc> {
        let reader = &mut &packet[..];
        let header = track_try!(rfc3550::RtpFixedHeader::read_from(reader));
        Ok(header.ssrc)
    }

    fn determine_incoming_packet_index(
        _context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
    ) -> Result<Self::PacketIndex> {
        let seq_num = track_try!(Srtp::parse_seq_num(packet));
        Ok(Srtp::estimate_packet_index(
            &ssrc_context.protocol_specific,
            seq_num,
        ))
    }

    fn determine_outgoing_packet_index(
        context: &SsrcContext<Self>,
        packet: &[u8],
    ) -> Result<Self::PacketIndex> {
        let seq_num = track_try!(Srtp::parse_seq_num(packet));
        Ok(Srtp::estimate_packet_index(
            &context.protocol_specific,
            seq_num,
        ))
    }

    fn get_authenticated_bytes<'a>(
        _context: &Context<Self>,
        index: Self::PacketIndex,
        auth_portion: &'a [u8],
    ) -> Result<Cow<'a, [u8]>> {
        // For SRTP, the ROC is part of the authenticated bytes (but not in the actual packet)
        let roc = (index >> 16) as u32;
        let mut auth_bytes = Vec::from(auth_portion);
        track_try!((&mut auth_bytes).write_u32be(roc));
        Ok(Cow::Owned(auth_bytes))
    }

    fn decrypt(
        context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>> {
        let reader = &mut &packet[..];
        let header = track_try!(rfc3550::RtpFixedHeader::read_from(reader));
        let ssrc = header.ssrc;
        let encrypted_portion = &reader[0..reader.len() - context.auth_tag_len];

        let mut decrypted: Vec<u8> = Vec::new();
        track_try!(header.write_to(&mut decrypted));
        context.decrypt_portion(ssrc_context, encrypted_portion, &mut decrypted, ssrc, index);
        Ok(decrypted)
    }

    fn encrypt(
        context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>> {
        let reader = &mut &packet[..];
        let header = track_try!(rfc3550::RtpFixedHeader::read_from(reader));
        let ssrc = header.ssrc;
        let plaintext_portion = &reader[0..];

        let mut encrypted: Vec<u8> = Vec::new();
        track_try!(header.write_to(&mut encrypted));
        context.encrypt_portion(ssrc_context, plaintext_portion, &mut encrypted, ssrc, index);
        Ok(encrypted)
    }

    fn update_highest_recv_index(context: &mut SsrcContext<Self>, index: Self::PacketIndex) {
        // https://tools.ietf.org/html/rfc3711#section-3.3.1
        let state = &mut context.protocol_specific;
        let rollover_counter = (index >> 16) as u32;
        let seq_num = index as u16;
        if rollover_counter == state.rollover_counter {
            if seq_num > state.highest_seq_num {
                state.highest_seq_num = seq_num;
            }
        } else if rollover_counter > state.rollover_counter {
            state.highest_seq_num = seq_num;
            state.rollover_counter = rollover_counter;
        }
    }

    fn update_highest_sent_index(context: &mut SsrcContext<Self>, index: Self::PacketIndex) {
        // Unless we assume that packets are properly ordered when sent,
        // we have to use the same algorithm to update the ROC as when receiving them.
        Self::update_highest_recv_index(context, index);
    }
}

impl Protocol for Srtcp {
    type PacketIndex = u32; // actually 31-bits
    const ENC_KEY_LABEL: u8 = 3;
    const AUTH_KEY_LABEL: u8 = 4;
    const SALT_KEY_LABEL: u8 = 5;

    fn read_ssrc(packet: &[u8]) -> Result<Ssrc> {
        let reader = &mut &packet[..];
        track_try!(reader.read_u32be());
        track_err!(reader.read_u32be())
    }

    fn determine_incoming_packet_index(
        context: &Context<Self>,
        _ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
    ) -> Result<Self::PacketIndex> {
        let reader = &mut &packet[packet.len() - context.auth_tag_len - 4..];
        let index = track_try!(reader.read_u32be());
        Ok(index & 0x7FFF_FFFF) // remove uppermost bit (aka. E-bit) which isn't part of the index
    }

    fn determine_outgoing_packet_index(
        context: &SsrcContext<Self>,
        _packet: &[u8],
    ) -> Result<Self::PacketIndex> {
        const MODULO: u32 = 1 << 31;
        Ok((context.protocol_specific.highest_sent_index + 1) % MODULO)
    }

    fn get_authenticated_bytes<'a>(
        _context: &Context<Self>,
        _index: Self::PacketIndex,
        auth_portion: &'a [u8],
    ) -> Result<Cow<'a, [u8]>> {
        // For SRTCP the full packet index is already part of the packet
        Ok(Cow::Borrowed(auth_portion))
    }

    fn decrypt(
        context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>> {
        let e_bit_reader = &mut &packet[packet.len() - context.auth_tag_len - 4..];
        let is_encrypted = track_try!(e_bit_reader.read_u32be()) & 0x8000_0000 != 0;
        if !is_encrypted {
            return Ok(Vec::from(
                &packet[..packet.len() - context.auth_tag_len - 4],
            ));
        }

        let reader = &mut &packet[..];
        let _ = track_try!(reader.read_u32be());
        let ssrc = track_try!(reader.read_u32be());
        let encrypted_portion = &reader[0..reader.len() - context.auth_tag_len - 4];

        let mut decrypted = Vec::from(&packet[..8]);
        context.decrypt_portion(ssrc_context, encrypted_portion, &mut decrypted, ssrc, index);
        Ok(decrypted)
    }

    fn encrypt(
        context: &Context<Self>,
        ssrc_context: &SsrcContext<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>> {
        let reader = &mut &packet[..];
        let _ = track_try!(reader.read_u32be());
        let ssrc = track_try!(reader.read_u32be());
        let plaintext_portion = &reader[0..];

        let mut encrypted = Vec::from(&packet[..8]);
        context.decrypt_portion(ssrc_context, plaintext_portion, &mut encrypted, ssrc, index);
        let index_with_e_bit = index | 0x8000_0000; // "encrypted"-bit
        track_try!(encrypted.write_u32be(index_with_e_bit));
        Ok(encrypted)
    }

    fn update_highest_recv_index(_context: &mut SsrcContext<Self>, _index: Self::PacketIndex) {
        // full packet inex is part of SRTCP packets, no need to keep track of it
    }

    fn update_highest_sent_index(context: &mut SsrcContext<Self>, index: Self::PacketIndex) {
        // we're giving out indices in strictly ascending order in determine_outgoing_packet_index
        context.protocol_specific.highest_sent_index = index;
    }
}

impl<P: Protocol> Context<P>
where
    u64: From<P::PacketIndex>,
{
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Self {
        Context {
            master_key: Vec::from(master_key),
            master_salt: Vec::from(master_salt),
            key_derivation_rate: 0,
            encryption: EncryptionAlgorithm::default(),
            authentication: AuthenticationAlgorithm::default(),
            auth_tag_len: 80 / 8,
            unknown_ssrcs: 0,
            ssrc_context: BTreeMap::new(),
        }
    }

    pub fn add_ssrc(&mut self, ssrc: Ssrc) {
        let ssrc_context = SsrcContext {
            replay_window_head: 0,
            replay_window: FixedBitSet::with_capacity(128),
            session_encr_key: vec![0; 128 / 8],
            session_salt_key: vec![0; 112 / 8],
            session_auth_key: vec![0; 160 / 8],
            protocol_specific: P::default(),
        };
        assert!(
            self.ssrc_context.insert(ssrc, ssrc_context).is_none(),
            "SSRC {} had already been added",
            ssrc
        );
    }

    pub fn add_unknown_ssrcs(&mut self, count: usize) {
        self.unknown_ssrcs += count;
    }

    pub fn update_session_keys(&mut self, ssrc: Ssrc, index: P::PacketIndex) {
        let index = if self.key_derivation_rate == 0 {
            0
        } else {
            u64::from(index) >> (self.key_derivation_rate - 1)
        };

        // TODO: only recalculate if index changed, probably also cache surrounding indices
        //       but make sure the initial updates happens

        let index = BigUint::from(index);

        let enc_key_id =
            BigUint::from_bytes_be(&[P::ENC_KEY_LABEL, 0, 0, 0, 0, 0, 0]) + index.clone();
        let auth_key_id =
            BigUint::from_bytes_be(&[P::AUTH_KEY_LABEL, 0, 0, 0, 0, 0, 0]) + index.clone();
        let salt_key_id =
            BigUint::from_bytes_be(&[P::SALT_KEY_LABEL, 0, 0, 0, 0, 0, 0]) + index.clone();
        let master_salt = BigUint::from_bytes_be(&self.master_salt);

        let context = self.ssrc_context.get_mut(&ssrc).unwrap();
        context.session_encr_key = prf_n(
            &self.master_key,
            enc_key_id ^ master_salt.clone(),
            context.session_encr_key.len(),
        );
        context.session_auth_key = prf_n(
            &self.master_key,
            auth_key_id ^ master_salt.clone(),
            context.session_auth_key.len(),
        );
        context.session_salt_key = prf_n(
            &self.master_key,
            salt_key_id ^ master_salt.clone(),
            context.session_salt_key.len(),
        );
    }

    pub fn authenticate(
        &self,
        context: &SsrcContext<P>,
        packet: &[u8],
        index: P::PacketIndex,
    ) -> Result<()> {
        let auth_portion = &packet[..packet.len() - self.auth_tag_len];
        let auth_tag = &packet[packet.len() - self.auth_tag_len..];

        let auth_bytes = track_try!(P::get_authenticated_bytes(self, index, auth_portion));

        let mut expected_tag = hmac_hash_sha1(&context.session_auth_key, &auth_bytes);
        expected_tag.truncate(self.auth_tag_len);
        track_assert_eq!(auth_tag, &expected_tag[..], ErrorKind::Invalid);
        Ok(())
    }

    pub fn generate_auth_tag(
        &self,
        context: &SsrcContext<P>,
        packet: &[u8],
        index: P::PacketIndex,
    ) -> Result<Vec<u8>> {
        let auth_bytes = track_try!(P::get_authenticated_bytes(self, index, packet));
        let mut tag = hmac_hash_sha1(&context.session_auth_key, &auth_bytes);
        tag.truncate(self.auth_tag_len);
        Ok(tag)
    }

    pub fn decrypt_portion(
        &self,
        context: &SsrcContext<P>,
        encrypted: &[u8],
        decrypted: &mut Vec<u8>,
        ssrc: u32,
        index: P::PacketIndex,
    ) {
        let iv = BigUint::from_bytes_be(&context.session_salt_key) << 16;
        let iv = iv ^ (BigUint::from(ssrc) << 64);
        let iv = iv ^ (Into::<BigUint>::into(index) << 16);
        let iv = iv ^ (BigUint::from(1_u8) << (context.session_encr_key.len() * 8));
        let iv = &iv.to_bytes_be()[1..context.session_encr_key.len() + 1];

        let mut ctr =
            aes_ctr::Aes128Ctr::new_var(&context.session_encr_key, iv).expect("Correct Key Length");

        let block_size = context.session_encr_key.len();

        for block in encrypted.chunks(block_size) {
            let old_len = decrypted.len();
            decrypted.extend_from_slice(block);
            ctr.apply_keystream(&mut decrypted[old_len..]);
        }
    }
    pub fn decrypt(
        &self,
        context: &SsrcContext<P>,
        packet: &[u8],
        index: P::PacketIndex,
    ) -> Result<Vec<u8>> {
        P::decrypt(self, context, packet, index)
    }

    pub fn encrypt_portion(
        &self,
        context: &SsrcContext<P>,
        plaintext: &[u8],
        encrypted: &mut Vec<u8>,
        ssrc: u32,
        index: P::PacketIndex,
    ) {
        let iv = BigUint::from_bytes_be(&context.session_salt_key) << 16;
        let iv = iv ^ (BigUint::from(ssrc) << 64);
        let iv = iv ^ (Into::<BigUint>::into(index) << 16);
        let iv = iv ^ (BigUint::from(1_u8) << (context.session_encr_key.len() * 8));
        let iv = &iv.to_bytes_be()[1..context.session_encr_key.len() + 1];

        let mut ctr =
            aes_ctr::Aes128Ctr::new_var(&context.session_encr_key, iv).expect("Correct Key Length");
        let block_size = context.session_encr_key.len();

        for block in plaintext.chunks(block_size) {
            let old_len = encrypted.len();
            encrypted.extend_from_slice(block);
            ctr.apply_keystream(&mut encrypted[old_len..]);
        }
    }
    pub fn encrypt(
        &self,
        context: &SsrcContext<P>,
        packet: &[u8],
        index: P::PacketIndex,
    ) -> Result<Vec<u8>> {
        P::encrypt(self, context, packet, index)
    }

    // https://tools.ietf.org/html/rfc3711#section-3.3
    // https://tools.ietf.org/html/rfc3711#section-3.4
    pub fn process_incoming(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // Step 1: determining the correct context
        let ssrc = track_try!(P::read_ssrc(packet));
        if !self.ssrc_context.contains_key(&ssrc) {
            track_assert!(
                self.unknown_ssrcs > 0,
                ErrorKind::Invalid,
                "Unknown SSRC {}",
                ssrc
            );
            self.unknown_ssrcs -= 1;
            let ssrc_context = SsrcContext {
                replay_window_head: 0,
                replay_window: FixedBitSet::with_capacity(128),
                session_encr_key: vec![0; 128 / 8],
                session_salt_key: vec![0; 112 / 8],
                session_auth_key: vec![0; 160 / 8],
                protocol_specific: P::default(),
            };
            self.ssrc_context.insert(ssrc, ssrc_context);
        }

        // Step 2: Determine index of the packet
        let index = track_try!(P::determine_incoming_packet_index(
            self,
            self.ssrc_context.get(&ssrc).unwrap(),
            packet
        ));

        // Step 3: Determine master key and salt
        // TODO: support re-keying
        // TODO: support MKI

        // Step 4: Determine session keys and salt
        self.update_session_keys(ssrc, index);

        let idx = u64::from(index);
        let (result, window_size) = {
            let ssrc_context = self.ssrc_context.get(&ssrc).unwrap();

            // Step 5: Replay protection and authentication
            let window_size = ssrc_context.replay_window.len() as u64;
            if idx <= ssrc_context.replay_window_head {
                track_assert!(
                    idx + window_size > ssrc_context.replay_window_head,
                    ErrorKind::Invalid
                );
                track_assert!(
                    !ssrc_context.replay_window[(idx % window_size) as usize],
                    ErrorKind::Invalid
                );
            }
            track_try!(self.authenticate(ssrc_context, packet, index));

            // Step 6: Decryption
            let result = track_try!(self.decrypt(ssrc_context, packet, index));

            (result, window_size)
        };
        {
            let ssrc_context = self.ssrc_context.get_mut(&ssrc).unwrap();

            // Step 7: Update ROC, highest sequence number and replay protection
            if idx > ssrc_context.replay_window_head {
                if idx - ssrc_context.replay_window_head >= window_size {
                    ssrc_context.replay_window.clear()
                } else {
                    let start = ((ssrc_context.replay_window_head + 1) % window_size) as usize;
                    let end = (idx % window_size) as usize;
                    if start > end {
                        ssrc_context.replay_window.set_range(start.., false);
                        ssrc_context.replay_window.set_range(..end, false);
                    } else {
                        ssrc_context.replay_window.set_range(start..end, false);
                    }
                }
                ssrc_context.replay_window_head = idx;
            }
            ssrc_context
                .replay_window
                .insert((idx % window_size) as usize);
            P::update_highest_recv_index(ssrc_context, index);
        };

        Ok(result)
    }

    // https://tools.ietf.org/html/rfc3711#section-3.3
    // https://tools.ietf.org/html/rfc3711#section-3.4
    pub fn process_outgoing(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // Step 1: determining the correct context
        let ssrc = track_try!(P::read_ssrc(packet));
        if !self.ssrc_context.contains_key(&ssrc) {
            track_assert!(
                self.unknown_ssrcs > 0,
                ErrorKind::Invalid,
                "Unknown SSRC {}",
                ssrc
            );
            self.unknown_ssrcs -= 1;
            let ssrc_context = SsrcContext {
                replay_window_head: 0,
                replay_window: FixedBitSet::with_capacity(128),
                session_encr_key: vec![0; 128 / 8],
                session_salt_key: vec![0; 112 / 8],
                session_auth_key: vec![0; 160 / 8],
                protocol_specific: P::default(),
            };
            self.ssrc_context.insert(ssrc, ssrc_context);
        }

        // Step 2: Determine index of the packet
        let index = track_try!(P::determine_outgoing_packet_index(
            self.ssrc_context.get(&ssrc).unwrap(),
            packet
        ));

        // Step 3: Determine master key and salt
        // TODO: support re-keying
        // TODO: support MKI

        // Step 4: Determine session keys and salt
        self.update_session_keys(ssrc, index);

        // Step 5: Encryption
        let mut result =
            track_try!(self.encrypt(self.ssrc_context.get(&ssrc).unwrap(), packet, index));

        // Step 6: Append MKI if MKI indicator is set
        // TODO: support MKI

        // Step 7: Signing
        let auth_tag = track_try!(self.generate_auth_tag(
            self.ssrc_context.get(&ssrc).unwrap(),
            &result[..],
            index
        ));
        result.extend(auth_tag);

        // Step 7: Update ROC and highest sequence number
        P::update_highest_sent_index(self.ssrc_context.get_mut(&ssrc).unwrap(), index);

        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpPacketReader<T> {
    context: Context<Srtp>,
    inner: T,
}
impl<T> SrtpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtpPacket,
{
    pub fn new(context: Context<Srtp>, inner: T) -> Self {
        SrtpPacketReader {
            context: context,
            inner: inner,
        }
    }
}
impl<T> ReadPacket for SrtpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtpPacket,
{
    type Packet = T::Packet;
    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Self::Packet> {
        let packet_bytes = track_try!(reader.read_all_bytes());
        let decrypted_packet_bytes = track_try!(self.context.process_incoming(&packet_bytes));
        track_err!(self.inner.read_packet(&mut &decrypted_packet_bytes[..]))
    }

    fn supports_type(&self, ty: u8) -> bool {
        self.inner.supports_type(ty)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpPacketWriter<T> {
    context: Context<Srtp>,
    inner: T,
}
impl<T> SrtpPacketWriter<T>
where
    T: WritePacket,
    T::Packet: RtpPacket,
{
    pub fn new(context: Context<Srtp>, inner: T) -> Self {
        SrtpPacketWriter {
            context: context,
            inner: inner,
        }
    }
}
impl<T> WritePacket for SrtpPacketWriter<T>
where
    T: WritePacket,
    T::Packet: RtpPacket,
{
    type Packet = T::Packet;
    fn write_packet<W: Write>(&mut self, writer: &mut W, packet: &T::Packet) -> Result<()> {
        let mut packet_bytes = Vec::new();
        track_try!(self.inner.write_packet(&mut packet_bytes, packet));
        let encrypted_packet_bytes = track_try!(self.context.process_outgoing(&packet_bytes));
        track_err!(writer.write_all(&encrypted_packet_bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtcpPacketReader<T> {
    context: Context<Srtcp>,
    inner: T,
}
impl<T> SrtcpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtcpPacket,
{
    pub fn new(context: Context<Srtcp>, inner: T) -> Self {
        SrtcpPacketReader {
            context: context,
            inner: inner,
        }
    }
}
impl<T> ReadPacket for SrtcpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtcpPacket,
{
    type Packet = T::Packet;
    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Self::Packet> {
        let packet_bytes = track_try!(reader.read_all_bytes());
        let decrypted_packet_bytes = track_try!(self.context.process_incoming(&packet_bytes));
        track_err!(self.inner.read_packet(&mut &decrypted_packet_bytes[..]))
    }

    fn supports_type(&self, ty: u8) -> bool {
        self.inner.supports_type(ty)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtcpPacketWriter<T> {
    context: Context<Srtcp>,
    inner: T,
}
impl<T> SrtcpPacketWriter<T>
where
    T: WritePacket,
    T::Packet: RtpPacket,
{
    pub fn new(context: Context<Srtcp>, inner: T) -> Self {
        SrtcpPacketWriter {
            context: context,
            inner: inner,
        }
    }
}
impl<T> WritePacket for SrtcpPacketWriter<T>
where
    T: WritePacket,
    T::Packet: RtpPacket,
{
    type Packet = T::Packet;
    fn write_packet<W: Write>(&mut self, writer: &mut W, packet: &T::Packet) -> Result<()> {
        let mut packet_bytes = Vec::new();
        track_try!(self.inner.write_packet(&mut packet_bytes, packet));
        let encrypted_packet_bytes = track_try!(self.context.process_outgoing(&packet_bytes));
        track_err!(writer.write_all(&encrypted_packet_bytes))
    }
}

fn hmac_hash_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = hmac::Hmac::<sha1::Sha1>::new_varkey(key).expect("Correct Key Length");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

fn prf_n(master_key: &[u8], x: BigUint, n: usize) -> Vec<u8> {
    // https://tools.ietf.org/html/rfc3711#section-4.1.1
    let mut output = Vec::new();
    let mut ctr = aes_ctr::Aes128Ctr::new_var(master_key, &(x << 16).to_bytes_be())
        .expect("Correct Key Length");

    output.reserve_exact(n.next_multiple_of(&16));

    for i in 0.. {
        let old_len = output.len();

        output.extend_from_slice(&[0u8; 8]);
        output.extend_from_slice(&u64::to_be_bytes(i));

        ctr.apply_keystream(&mut output[old_len..]);
        if output.len() >= n {
            break;
        }
    }
    output.truncate(n);
    output
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::rfc3550;
    use crate::rfc4585;

    #[test]
    fn rtp_packet_index_estimation_works() {
        let mut context = Srtp::default();
        let roc = 0u32;
        let roc_n1 = roc.wrapping_sub(1);
        let roc_p1 = roc.wrapping_add(1);
        context.rollover_counter = roc;

        let i = |roc, seq_num| ((roc as u64) << 16) + seq_num as u64;
        let estimate = |ctx: &Srtp, seq_num| Srtp::estimate_packet_index(ctx, seq_num);

        context.highest_seq_num = 1000; // low highest_seq_num
        assert_eq!(estimate(&context, 1), i(roc, 1)); // lower but same roc
        assert_eq!(estimate(&context, 10001), i(roc, 10001)); // higher but same roc
        assert_eq!(estimate(&context, 60001), i(roc_n1, 60001)); // roc-1
        context.highest_seq_num = 60000; // high highest_seq_num
        assert_eq!(estimate(&context, 60001), i(roc, 60001)); // higher but same roc
        assert_eq!(estimate(&context, 30001), i(roc, 30001)); // lower but same roc
        assert_eq!(estimate(&context, 10001), i(roc_p1, 10001)); // roc+1
    }

    pub(crate) const TEST_MASTER_KEY: &[u8] = &[
        211, 77, 116, 243, 125, 116, 231, 95, 59, 219, 79, 118, 241, 189, 244, 119,
    ];
    pub(crate) const TEST_MASTER_SALT: &[u8] = &[
        127, 31, 227, 93, 120, 247, 126, 117, 231, 159, 123, 235, 95, 122,
    ];
    pub(crate) const TEST_SRTP_SSRC: Ssrc = 446919554;
    pub(crate) const TEST_SRTP_PACKET: &[u8] = &[
        128, 0, 3, 92, 222, 161, 6, 76, 26, 163, 115, 130, 222, 0, 143, 87, 0, 227, 123, 91, 200,
        238, 141, 220, 9, 191, 52, 111, 100, 62, 220, 158, 211, 79, 184, 199, 79, 182, 9, 248, 170,
        82, 125, 152, 143, 206, 8, 152, 80, 207, 27, 183, 141, 77, 33, 60, 101, 180, 210, 146, 139,
        170, 149, 13, 99, 75, 223, 156, 79, 71, 84, 119, 68, 236, 244, 163, 198, 175, 219, 160,
        255, 9, 82, 169, 64, 112, 106, 4, 0, 246, 39, 29, 88, 15, 62, 174, 21, 253, 171, 198, 128,
        61, 23, 43, 143, 255, 176, 125, 223, 23, 188, 90, 103, 139, 223, 56, 162, 35, 27, 225, 117,
        243, 138, 163, 35, 79, 221, 201, 149, 154, 203, 255, 2, 23, 184, 184, 169, 32, 1, 138, 172,
        60, 70, 240, 53, 11, 54, 81, 172, 214, 34, 136, 39, 152, 17, 247, 126, 199, 200, 184, 70,
        7, 52, 191, 129, 239, 86, 78, 172, 229, 178, 112, 22, 125, 191, 164, 17, 193, 24, 152, 197,
        146, 94, 74, 156, 171, 245, 239, 220, 205, 145, 206,
    ];
    pub(crate) const TEST_SRTCP_SSRC: Ssrc = 3270675037;
    pub(crate) const TEST_SRTCP_PACKET: &[u8] = &[
        128, 201, 0, 1, 194, 242, 138, 93, 177, 31, 99, 88, 187, 209, 173, 181, 135, 18, 79, 59,
        119, 153, 115, 34, 75, 94, 96, 29, 32, 14, 118, 86, 145, 159, 203, 174, 225, 34, 196, 229,
        39, 22, 174, 54, 198, 56, 179, 171, 111, 229, 48, 234, 138, 249, 127, 11, 86, 94, 40, 213,
        87, 203, 60, 54, 52, 60, 10, 93, 128, 0, 0, 1, 114, 135, 74, 73, 233, 100, 85, 240, 125,
        93,
    ];

    const TEST_2_MASTER_KEY: &[u8] = &[
        124, 185, 61, 185, 219, 148, 249, 33, 222, 227, 189, 112, 23, 80, 114, 233,
    ];
    const TEST_2_MASTER_SALT: &[u8] = &[93, 4, 23, 245, 147, 199, 112, 49, 24, 105, 140, 1, 77, 98];
    const TEST_2_SRTP_SSRC: Ssrc = 180601533;
    const TEST_2_SRTP_PACKET_BEFORE_ROLLOVER: &[u8] = &[
        0x80, 0x61, 0xff, 0xff, 0x87, 0xf5, 0xee, 0x93, 0x0a, 0xc3, 0xc2, 0xbd, 0x93, 0x04, 0x0b,
        0x4d, 0xe9, 0x55, 0x69, 0xb7, 0xac, 0x88, 0xc5, 0xd6, 0xc2, 0x75, 0xb8, 0x15, 0x86, 0xc3,
        0xb2, 0x2a, 0x34, 0x64, 0xbe, 0x8b, 0x0d, 0x61, 0xfc, 0x22, 0xf1, 0x30, 0x66, 0xe0, 0x1e,
        0x1d, 0x0c, 0xec, 0xff, 0x8d, 0xff, 0x86, 0xf7, 0xf4, 0x7e, 0x40, 0x8a, 0xd0, 0x36, 0x3f,
        0x67, 0x60, 0x0f, 0xbd, 0x46, 0xa9, 0x3e, 0xa5, 0x4b, 0x31, 0x54, 0xc8, 0x45, 0x61, 0xc8,
        0x33, 0x68, 0x2b, 0x0c, 0x98, 0x5f, 0x61, 0x68, 0xc4, 0x32, 0x8f, 0x70, 0xc4, 0xc6, 0x05,
        0x7e, 0x30, 0xcf, 0x67, 0x78, 0xf4, 0x50, 0x1b, 0xba, 0x5f, 0x10, 0x5f, 0xf6, 0x6b, 0x99,
        0x6d, 0x68, 0xb8, 0x87, 0x21, 0x46, 0xd1, 0x4a, 0x4a,
    ];
    const TEST_2_SRTP_PACKET_AFTER_ROLLOVER: &[u8] = &[
        128, 97, 0, 0, 135, 245, 242, 83, 10, 195, 194, 189, 254, 253, 61, 217, 224, 102, 52, 18,
        244, 100, 144, 73, 190, 225, 100, 195, 28, 35, 116, 15, 37, 91, 236, 28, 24, 134, 223, 188,
        129, 1, 164, 18, 143, 87, 6, 25, 195, 159, 33, 147, 36, 175, 190, 60, 215, 204, 240, 27,
        186, 247, 223, 217, 65, 189, 66, 59, 3, 214, 53, 146, 32, 234, 27, 127, 211, 58, 156, 25,
        139, 236, 11, 138, 245, 134, 84, 164, 130, 226, 90, 74, 131, 57, 100, 0, 106, 127, 239,
        184, 235, 197, 164, 15, 233, 146, 84, 127, 42, 9, 100,
    ];

    #[test]
    fn rtp_decryption_works() {
        let mut context = Context::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        context.add_ssrc(TEST_SRTP_SSRC);
        let mut rtp_reader = SrtpPacketReader::new(context, rfc3550::RtpPacketReader);
        let packet = rtp_reader.read_packet(&mut TEST_SRTP_PACKET).unwrap();

        let expected_prefix = [
            0xbe, 0x9c, 0x8c, 0x86, 0x81, 0x80, 0x81, 0x86, 0x8d, 0x9c, 0xfd, 0x1b, 0x0d, 0x05,
            0x01, 0x00, 0x01, 0x05, 0x0d, 0x1b, 0xff, 0x9b, 0x8d, 0x85, 0x81, 0x80, 0x81, 0x85,
            0x8d, 0x9b, 0xff, 0x1b,
        ];

        assert_eq!(
            &packet.payload[..expected_prefix.len()],
            &expected_prefix[..]
        );
    }

    #[test]
    fn rtp_decryption_with_rollover_works() {
        let mut context = Context::<Srtp>::new(&TEST_2_MASTER_KEY, &TEST_2_MASTER_SALT);
        context.add_ssrc(TEST_2_SRTP_SSRC);
        context
            .ssrc_context
            .get_mut(&TEST_2_SRTP_SSRC)
            .unwrap()
            .protocol_specific
            .highest_seq_num = 65534;
        let mut rtp_reader = SrtpPacketReader::new(context, rfc3550::RtpPacketReader);
        rtp_reader
            .read_packet(&mut TEST_2_SRTP_PACKET_BEFORE_ROLLOVER)
            .unwrap();
        rtp_reader
            .read_packet(&mut TEST_2_SRTP_PACKET_AFTER_ROLLOVER)
            .unwrap();
    }

    #[test]
    fn rtcp_decryption_works() {
        let master_key = [
            254, 123, 44, 240, 174, 252, 53, 54, 2, 213, 123, 106, 85, 165, 5, 13,
        ];
        let master_salt = [
            77, 202, 202, 112, 81, 101, 219, 232, 143, 131, 160, 89, 15, 141,
        ];
        let packet = [
            128, 201, 0, 1, 194, 242, 138, 93, 67, 38, 193, 233, 60, 78, 188, 195, 230, 90, 19,
            196, 152, 235, 136, 164, 15, 177, 174, 217, 207, 115, 148, 223, 109, 112, 71, 245, 16,
            214, 216, 232, 87, 153, 5, 238, 72, 201, 223, 43, 69, 99, 54, 211, 118, 28, 227, 100,
            161, 216, 90, 203, 99, 167, 215, 130, 151, 16, 128, 138, 128, 0, 0, 1, 126, 39, 201,
            236, 161, 194, 6, 232, 194, 230,
        ];

        let mut context = Context::new(&master_key, &master_salt);
        context.add_ssrc(TEST_SRTCP_SSRC);
        let mut rtcp_reader = SrtcpPacketReader::new(context, rfc4585::RtcpPacketReader);
        let packet = track_try_unwrap!(rtcp_reader.read_packet(&mut &packet[..]));
        println!("# {:?}", packet);
    }

    #[test]
    fn rtp_decryption_encryption_are_inverse() {
        let mut dec_context = Context::<Srtp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        let mut enc_context = Context::<Srtp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        dec_context.add_ssrc(TEST_SRTP_SSRC);
        enc_context.add_ssrc(TEST_SRTP_SSRC);
        let decrypted = track_try_unwrap!(dec_context.process_incoming(TEST_SRTP_PACKET));
        let encrypted = track_try_unwrap!(enc_context.process_outgoing(&decrypted));
        assert_eq!(&encrypted[..], TEST_SRTP_PACKET);
    }

    #[test]
    fn rtcp_decryption_encryption_are_inverse() {
        let mut dec_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        let mut enc_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        dec_context.add_ssrc(TEST_SRTCP_SSRC);
        enc_context.add_ssrc(TEST_SRTCP_SSRC);
        let decrypted = track_try_unwrap!(dec_context.process_incoming(TEST_SRTCP_PACKET));
        let encrypted = track_try_unwrap!(enc_context.process_outgoing(&decrypted));
        assert_eq!(&encrypted[..], TEST_SRTCP_PACKET);
    }

    #[test]
    fn rtcp_encryption_does_not_use_two_time_pad() {
        let mut dec_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        let mut enc_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        dec_context.add_ssrc(TEST_SRTCP_SSRC);
        enc_context.add_ssrc(TEST_SRTCP_SSRC);
        let decrypted = track_try_unwrap!(dec_context.process_incoming(TEST_SRTCP_PACKET));
        let encrypted_1 = track_try_unwrap!(enc_context.process_outgoing(&decrypted));
        let encrypted_2 = track_try_unwrap!(enc_context.process_outgoing(&decrypted));
        let encrypted_3 = track_try_unwrap!(enc_context.process_outgoing(&decrypted));
        assert_ne!(encrypted_1, encrypted_2);
        assert_ne!(encrypted_1, encrypted_3);
        assert_ne!(encrypted_2, encrypted_3);
    }

    #[test]
    fn rtp_does_not_allow_packet_replay() {
        let mut dec_context = Context::<Srtp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        dec_context.add_ssrc(TEST_SRTP_SSRC);
        assert!(dec_context.process_incoming(TEST_SRTP_PACKET).is_ok());
        assert!(dec_context.process_incoming(TEST_SRTP_PACKET).is_err());
        assert!(dec_context.process_incoming(TEST_SRTP_PACKET).is_err());
    }

    #[test]
    fn rtcp_does_not_allow_packet_replay() {
        let mut dec_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        dec_context.add_ssrc(TEST_SRTCP_SSRC);
        assert!(dec_context.process_incoming(TEST_SRTCP_PACKET).is_ok());
        assert!(dec_context.process_incoming(TEST_SRTCP_PACKET).is_err());
        assert!(dec_context.process_incoming(TEST_SRTCP_PACKET).is_err());
    }

    #[test]
    fn rtcp_does_not_allow_delayed_packet_replay() {
        let mut dec_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        dec_context.add_ssrc(TEST_SRTCP_SSRC);
        let decrypted = dec_context.process_incoming(TEST_SRTCP_PACKET).unwrap();

        let mut enc_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        enc_context.add_ssrc(TEST_SRTCP_SSRC);
        const N: usize = 10;
        let encs: Vec<_> = (0..N)
            .map(|_| enc_context.process_outgoing(&decrypted).unwrap())
            .collect();

        let mut dec_context = Context::<Srtcp>::new(&TEST_MASTER_KEY, &TEST_MASTER_SALT);
        dec_context.add_ssrc(TEST_SRTCP_SSRC);
        dec_context
            .ssrc_context
            .get_mut(&TEST_SRTCP_SSRC)
            .unwrap()
            .replay_window = FixedBitSet::with_capacity(4);

        assert!(dec_context.process_incoming(&encs[0]).is_ok());
        assert!(dec_context.process_incoming(&encs[1]).is_ok());
        assert!(dec_context.process_incoming(&encs[2]).is_ok());
        assert!(dec_context.process_incoming(&encs[3]).is_ok());
        assert!(dec_context.process_incoming(&encs[4]).is_ok());
        assert!(dec_context.process_incoming(&encs[5]).is_ok());
        assert!(dec_context.process_incoming(&encs[0]).is_err());
        assert!(dec_context.process_incoming(&encs[1]).is_err());
        assert!(dec_context.process_incoming(&encs[2]).is_err());
        assert!(dec_context.process_incoming(&encs[3]).is_err());
        assert!(dec_context.process_incoming(&encs[4]).is_err());
        assert!(dec_context.process_incoming(&encs[5]).is_err());

        assert!(dec_context.process_incoming(&encs[7]).is_ok());
        assert!(dec_context.process_incoming(&encs[6]).is_ok());
        assert!(dec_context.process_incoming(&encs[3]).is_err());
        assert!(dec_context.process_incoming(&encs[4]).is_err());
        assert!(dec_context.process_incoming(&encs[5]).is_err());
        assert!(dec_context.process_incoming(&encs[6]).is_err());
        assert!(dec_context.process_incoming(&encs[7]).is_err());

        assert!(dec_context.process_incoming(&encs[9]).is_ok());
        assert!(dec_context.process_incoming(&encs[8]).is_ok());
        assert!(dec_context.process_incoming(&encs[5]).is_err());
        assert!(dec_context.process_incoming(&encs[6]).is_err());
        assert!(dec_context.process_incoming(&encs[7]).is_err());
        assert!(dec_context.process_incoming(&encs[8]).is_err());
        assert!(dec_context.process_incoming(&encs[9]).is_err());
    }
}

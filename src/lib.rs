#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn packing() {
        let keys = load_keys("key_retail.bin").unwrap(); // commiting crimes time :grin:
        // this is emitted from amiitool, which is known to produce good bins
        let sample_signed  : [u8; AMIIBO_SIZE] = std::fs::read("sample_signed.bin").unwrap().try_into().unwrap(); 
        // this is an unencrpyted file
        let sample_unsigned : [u8; AMIIBO_SIZE]= std::fs::read("sample2_unsigned.bin").unwrap().try_into().unwrap();

        let packed_sample : [u8; AMIIBO_SIZE] = amiibo_pack(&keys, sample_unsigned.into()).unwrap().into();
        std::fs::write("testpack.bin", packed_sample).unwrap(); 
        assert_eq!(packed_sample, sample_signed);
    }
    #[test]
    fn unpacking() {
        let keys = load_keys("key_retail.bin").unwrap();
        let sample_signed : [u8; AMIIBO_SIZE] = std::fs::read("sample_signed.bin").unwrap().try_into().unwrap();
        let sample_unsigned : [u8; AMIIBO_SIZE] = std::fs::read("sample2_unsigned.bin").unwrap().try_into().unwrap();

        let unpacked_sample : [u8; AMIIBO_SIZE] = amiibo_unpack(&keys, sample_signed.into()).unwrap().get_checked().expect("Invalid signature").into();
        std::fs::write("testunpack.bin", unpacked_sample).unwrap();
        assert_eq!(unpacked_sample, sample_unsigned);
    }
}

const KEYGEN_SEED_SIZE: usize = 64;
const DRBG_OUTPUT_SIZE: usize = 32;
use hmac::Mac;
use sha2::Sha256;
use std::io;
use std::io::{Cursor, Write};
#[derive(Copy, Clone, Debug)]
pub struct MasterKeys {
    pub hmac_key: [u8; 16],
    pub type_string: [u8; 14],
    pub magic_bytes_size: u8,
    pub magic_bytes: [u8; 16],
    pub xor_pad: [u8; 32],
}
#[derive(Default,Copy, Clone,Debug)]
struct DerivedKeys {
    aes_key: [u8; 16],
    aes_iv: [u8; 16],
    hmac_key: [u8; 16],
}
#[derive(Debug, Copy, Clone)]
pub struct PackedAmiibo {
    amiibo: [u8; AMIIBO_SIZE]
}

#[derive(Debug, Copy, Clone)]
pub struct PlainAmiibo {
    amiibo: [u8; AMIIBO_SIZE]
}
impl PlainAmiibo {
    pub fn amiibo_id(&self) -> [u8; 8] {
        self.amiibo[0x1DC..=0x1E3].try_into().unwrap()
    }
    pub fn character_id(&self) -> [u8; 2] {
        self.amiibo[0x1DC..=0x1DD].try_into().unwrap()
    }
    pub fn nickname(&self) -> String {
        let mut name_buf : [u8; 20] = self.amiibo[0x38..=0x4B].try_into().unwrap();
        for i in (0usize..20usize).step_by(2) {
            let tmp = name_buf[i];
            name_buf[i] = name_buf[i + 1];
            name_buf[i + 1] = tmp;
        }
        let utf16_buf : [u16; 10] = name_buf.chunks(2).map(|x| u16::from_le_bytes(x.try_into().unwrap())).collect::<Vec<u16>>().try_into().unwrap();
        String::from_utf16_lossy(&utf16_buf)
    }
    pub fn mii_name(&self) -> String {
        let name_buf : [u16; 10] = self.amiibo[0x66..=0x79].chunks(2).map(|x| u16::from_le_bytes(x.try_into().unwrap())).collect::<Vec<u16>>().try_into().unwrap();
        String::from_utf16_lossy(&name_buf)
    }
    
}
impl From<[u8; AMIIBO_SIZE]> for PackedAmiibo {
    fn from(amiibo: [u8; AMIIBO_SIZE]) -> Self {
        PackedAmiibo { amiibo } 
    } 
}
impl From<[u8; AMIIBO_SIZE]> for PlainAmiibo {
    fn from(amiibo: [u8; AMIIBO_SIZE]) -> Self {
        PlainAmiibo { amiibo }
    }
}
impl From<PlainAmiibo> for [u8; AMIIBO_SIZE] {
    fn from(thing: PlainAmiibo) -> [u8; AMIIBO_SIZE] {
        thing.amiibo
    }
}
impl From<PackedAmiibo> for [u8; AMIIBO_SIZE] {
    fn from(thing: PackedAmiibo) -> [u8; AMIIBO_SIZE] {
        thing.amiibo
    }
}

impl TryFrom<&[u8]> for PackedAmiibo {
    type Error = std::array::TryFromSliceError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr = slice.try_into()?;
        Ok(PackedAmiibo { amiibo: arr })
    }
}

impl TryFrom<&[u8]> for PlainAmiibo {
    type Error = std::array::TryFromSliceError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr = slice.try_into()?;
        Ok(PlainAmiibo { amiibo: arr })
    }
}

impl PlainAmiibo {
    pub fn pack(self, amiibo_keys: &AmiiboKeys) -> Result<PackedAmiibo, AmiitoolError> {
        let plain : [u8; AMIIBO_SIZE] = self.into();
        let mut cipher = [0; AMIIBO_SIZE];

        // generate keys
        let tag_keys = amiibo_keygen(&amiibo_keys.tag, plain)?;
        let data_keys = amiibo_keygen(&amiibo_keys.data, plain)?;
        cipher[len_range(HMAC_POS_TAG, DRBG_OUTPUT_SIZE)].copy_from_slice(&compute_hmac(tag_keys.hmac_key, &plain, 0x1d4, 0x34));
        let mut data = Vec::new();
        // data
        data.extend_from_slice(&plain[len_range(0x29, 0x18B)]);
        data.extend_from_slice(&cipher[len_range(HMAC_POS_TAG,0x20)]); // Tag HMAC
        data.extend_from_slice(&plain[len_range(0x1D4, 0x34)]); // Unknown
        cipher[len_range(HMAC_POS_DATA, DRBG_OUTPUT_SIZE)].copy_from_slice(&compute_hmac(data_keys.hmac_key, data.as_slice(), 0, data.len()));

        // encrypt
        amiibo_cipher(&data_keys, plain, &mut cipher); 
        let mut packed = amiibo_internal_to_tag(cipher);
        // why is this here :sob: 
        memcpy(&mut packed, 0x208, &plain, 0x208, 0x14);
        Ok(packed.into())
    }
    pub fn generate(amiibo_id: [u8; 8], tag_uid: &[u8]) -> Result<Self, AmiitoolError> {
        if tag_uid.len() != 7 && tag_uid.len() != 9 {
            Err(AmiitoolError { why: "Not a 7 or 9 byte tag uid".to_string() } )
        } else {
            if tag_uid[0] != 0x04 {
                return Err(AmiitoolError { why: "Not a valid tag uid".to_string()});
            }
            let (small_uid, bcc1, uid) = match tag_uid.len() {
                7 => {
                    let bcc0 = 0x88 ^ tag_uid[0] ^ tag_uid[1] ^ tag_uid[2];
                    let bcc1 = tag_uid[3] ^ tag_uid[4] ^ tag_uid[5] ^ tag_uid[6];
                    (
                        tag_uid.try_into().expect("Already checked size"),
                        bcc1,
                        [
                            tag_uid[0], tag_uid[1], tag_uid[2], bcc0, tag_uid[3], tag_uid[4], tag_uid[5],
                            tag_uid[6],
                        ]
                    )
                }
                9 => {
                    let small_uid = [
                        tag_uid[0], tag_uid[1], tag_uid[2], tag_uid[4], tag_uid[5], tag_uid[6], tag_uid[7]
                    ];
                    (small_uid, tag_uid[8], tag_uid[0..8].try_into().expect("Fixed slice length"))
                }
                _ => unreachable!()
            };

            let pw1 = 0xAA ^ small_uid[1] ^ small_uid[3];
            let pw2 = 0x55 ^ small_uid[2] ^ small_uid[4];
            let pw3 = 0xAA ^ small_uid[3] ^ small_uid[5];
            let pw4 = 0x55 ^ small_uid[4] ^ small_uid[6];
            let mut amiibo : [u8; AMIIBO_SIZE] = [0; AMIIBO_SIZE];
            // set UID
            amiibo[len_range(0x1d4, 8)].copy_from_slice(&uid);
            amiibo[len_range(0,8)].copy_from_slice(&[bcc1, 0x48, 0 ,0 , 0xF1, 0x10, 0xFF, 0xEE]);
            // 0xA5 byte, write counter, unknown
            amiibo[len_range(0x28, 4)].copy_from_slice(&[0xA5, 0,0,0]); 
            // CFG 0 
            amiibo[0x20F] = 0x04;
            // CFG 1
            amiibo[len_range(0x210, 4)].copy_from_slice(&[0x5F,0,0,0]);
            // dynamic lock bits and RFUI
            amiibo[len_range(0x208, 4)].copy_from_slice(&[0x01, 0x00, 0x0F, 0xBD]);
            amiibo[0x214] = pw1;
            amiibo[0x215] = pw2;
            amiibo[0x216] = pw3;
            amiibo[0x217] = pw4; 
            amiibo[0x218] = 0x80;
            amiibo[0x219] = 0x80;
            // keygen salt
            let mut rng = rand::thread_rng();
            rng.fill(&mut amiibo[len_range(0x1E8, 32)]);
            // TODO: this depends on input being big endian 
            // amiibo id 
            amiibo[len_range(0x1DC, 8)].copy_from_slice(&amiibo_id);

            Ok(amiibo.into())    
        }
    }
}
impl PackedAmiibo {
    pub fn unpack(self, amiibo_keys: &AmiiboKeys) -> Result<UnverifiedAmiibo, AmiitoolError> {
        let tag : [u8; AMIIBO_SIZE] = self.into();
        // convert format
        let intl = amiibo_tag_to_internal(tag);

        // Generate keys
        let data_keys = amiibo_keygen(&amiibo_keys.data, intl)?;
        let tag_keys = amiibo_keygen(&amiibo_keys.tag, intl)?;

        // decrypt
        let mut plain = null_cipher(&data_keys, intl);
        let cur_plain = plain.clone();
        // Regenerate tag HMAC. Order matters, data HMAC depends on tag HMAC.
        plain[len_range(HMAC_POS_TAG, DRBG_OUTPUT_SIZE)].copy_from_slice(&compute_hmac(tag_keys.hmac_key, &cur_plain, 0x1d4, 0x34));

        // Regenerate data HMAC.
        let cur_plain = plain.clone();
        plain[len_range(HMAC_POS_DATA, DRBG_OUTPUT_SIZE)].copy_from_slice(&compute_hmac(data_keys.hmac_key, &cur_plain, 0x29, 0x1df));
        // idk what it does so i get rid of it
        memcpy(&mut plain, 0x208, &tag, 0x208, 0x14);
        Ok(UnverifiedAmiibo {data: plain, intl} )
    }
    pub fn generate(amiibo_id: [u8; 8], tag_uid: &[u8], amiibo_keys: &AmiiboKeys) -> Result<Self, AmiitoolError> {
        let plain = PlainAmiibo::generate(amiibo_id, tag_uid)?;
        plain.pack(amiibo_keys)
    }
}
#[derive(Clone, Debug)]
pub struct AmiitoolError {
    pub why : String
}

impl From<AmiitoolError> for io::Error {
    fn from(err: AmiitoolError) -> Self {
        io::Error::new(io::ErrorKind::Other, err.why)
    }
}
impl From<io::Error> for AmiitoolError {
    fn from(err: io::Error) -> Self {
        AmiitoolError { why: format!("{}",err) }
    }
}
impl std::fmt::Display for AmiitoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Amiitool error: {}", self.why)
    }
}
#[inline]
fn len_range(start: usize, len : usize) -> std::ops::Range<usize> {
    start..start+len
}
fn memcpy<T:Copy>(dest: &mut [T], dest_offset: usize, source: &[T], source_offset: usize, len : usize) {
    dest[len_range(dest_offset, len)].copy_from_slice(&source[len_range(source_offset, len)])
}
fn keygen_prepare_seed(base_keys: &MasterKeys, base_seed: [u8; KEYGEN_SEED_SIZE]) -> Result<Vec<u8>, AmiitoolError> {
    if base_keys.magic_bytes_size > 16 {
       return Err(AmiitoolError { why : "magic byte size too big".to_string() } ); 
    }

    let mut cursor = Cursor::new(Vec::new());
    // this is meant to get all things
    let da_str : Vec<u8>= base_keys.type_string.iter().take_while(|x| **x != 0).copied().collect();
    // 1: Copy whole type string
    cursor.write(&da_str)?;
    // this single line fixes the entire lib. ffk;afoih
    // putting my thinking cap on this is the `\0` at the end of a C string 
    cursor.write(&[0])?;

    
    // 2 : append (16 - magic_bytes_size) from the base seed
    let lead_size: usize = 16 - base_keys.magic_bytes_size as usize;
    // again, prints the same as amiitool
    cursor.write(&base_seed[len_range(0, lead_size)])?;
    // 3: append all bytes from magic bytes
    cursor.write(&base_keys.magic_bytes[0..base_keys.magic_bytes_size as usize])?;
    // 4: Append bytes 0x10-0x1F
    cursor.write(&base_seed[len_range(0x10,16)])?;
    for i in 0..32 {
        cursor.write(&[base_seed[i + 32] ^ base_keys.xor_pad[i]])?;
    }
    let vec = cursor.into_inner();
    Ok(vec)
}

fn keygen_gen(base_keys: &MasterKeys, base_seed: [u8; KEYGEN_SEED_SIZE]) -> Result<DerivedKeys, AmiitoolError> {
    let res = keygen_prepare_seed(base_keys, base_seed)?;
    let bytes = drbg_gen_bytes(base_keys.hmac_key, &res);
    Ok(bytes)
}
fn drbg_init(hmac_key: [u8; 16]) -> Hmac256 {
    Hmac256::new_from_slice(&hmac_key).expect("fixed slice length")
}
fn drbg_step(hmac: &mut Hmac256, seed: &[u8], iteration: &mut u16) -> [u8; DRBG_OUTPUT_SIZE] {
    let mut vec = Vec::new();
    vec.extend_from_slice(&u16::to_be_bytes(*iteration));
    vec.extend_from_slice(&seed);
    *iteration += 1;
    hmac.update(vec.as_slice());
    hmac.finalize_reset().into_bytes().try_into().unwrap()
}

type Hmac256 = hmac::Hmac<Sha256>;
fn drbg_gen_bytes<'a>(hmac_key: [u8; 16], seed: &[u8]) -> DerivedKeys {
    let mut i = 0;
    let mut out = [0u8; 48];
    let mut hmac = drbg_init(hmac_key);
    out[0..32].copy_from_slice(&drbg_step(&mut hmac, seed, &mut i));
    out[32..48].copy_from_slice(&drbg_step(&mut hmac, seed, &mut i)[0..16]);
    DerivedKeys { 
        aes_key : out[0..16].try_into().expect("Fixed slice size"),
        aes_iv: out[16..32].try_into().expect("fixed slice size"),
        hmac_key: out[32..48].try_into().expect("fixed slice size")
    }
}
pub const AMIIBO_SIZE: usize = 540;
fn amiibo_calc_seed(dump: [u8; AMIIBO_SIZE]) -> [u8; KEYGEN_SEED_SIZE] {
    let mut key: [u8; KEYGEN_SEED_SIZE] = [0; KEYGEN_SEED_SIZE];
    memcpy(&mut key, 0x00, &dump, 0x029, 0x02);
    key[len_range(2, 0xE)].fill(0);
    memcpy(&mut key, 0x10, &dump, 0x1D4, 0x08);
    memcpy(&mut key, 0x18, &dump, 0x1D4, 0x08);
    memcpy(&mut key, 0x20, &dump, 0x1E8, 0x20);
    key
}
fn amiibo_keygen(master_keys: &MasterKeys, dump: [u8; AMIIBO_SIZE]) -> Result<DerivedKeys, AmiitoolError> {
    let seed = amiibo_calc_seed(dump);
    keygen_gen(master_keys, seed)
}

use aes::cipher::{KeyIvInit, StreamCipher};
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
// slightly wrong output on not real inputs
fn amiibo_cipher(derived_keys: &DerivedKeys, input: [u8; AMIIBO_SIZE], out: &mut[u8; AMIIBO_SIZE]) -> () {
    let mut cipher: Aes128Ctr =
        Aes128Ctr::new(&derived_keys.aes_key.into(), &derived_keys.aes_iv.into());

    
    cipher.apply_keystream_b2b(&input[len_range(0x2c, 0x188)], &mut out[len_range(0x2c, 0x188)]).unwrap();
    memcpy(out, 0, &input, 0, 0x8);
    // data sig NOT copied
    memcpy(out, 0x28, &input, 0x28, 0x4);
    // tag sig NOT copied
    memcpy(out, 0x1d4, &input, 0x1d4, 0x34);

}
fn null_cipher(derived_keys: &DerivedKeys, input: [u8; AMIIBO_SIZE]) -> [u8; AMIIBO_SIZE] {
    let mut out = [0; AMIIBO_SIZE];
    amiibo_cipher(derived_keys, input, &mut out);
    out 
}
fn amiibo_tag_to_internal(tag: [u8; AMIIBO_SIZE]) -> [u8; AMIIBO_SIZE] {
    let mut out = [0; AMIIBO_SIZE];
    // BCC1, internal, static lock, CC
    memcpy(&mut out, 0x0, &tag, 0x8, 0x8);
    // unfixed hash
    memcpy(&mut out, 0x8, &tag, 0x80, 0x20);
    // pages 4-12 inclusive
    memcpy(&mut out, 0x28, &tag, 0x10, 0x24);
    // pages 40-129 inclusive 
    memcpy(&mut out, 0x4c, &tag, 0xa0, 0x168);
    // pages 13 to 20 inclusive 
    memcpy(&mut out, 0x1b4, &tag, 0x34, 0x20);
    // UID 
    memcpy(&mut out, 0x1d4, &tag, 0x0, 0x8);
    // amiibo id
    memcpy(&mut out, 0x1dc, &tag, 0x54, 0x2c);
    out.try_into().unwrap()
}

fn amiibo_internal_to_tag(internal: [u8; AMIIBO_SIZE]) -> [u8; AMIIBO_SIZE] {
    let mut out = [0;  AMIIBO_SIZE];
    memcpy(&mut out, 0x008, &internal, 0x000, 0x008);
    memcpy(&mut out, 0x080, &internal, 0x008, 0x020);
    memcpy(&mut out, 0x010, &internal, 0x028, 0x024);
    memcpy(&mut out, 0x0A0, &internal, 0x04C, 0x168);
    memcpy(&mut out, 0x034, &internal, 0x1B4, 0x020);
    memcpy(&mut out, 0x000, &internal, 0x1D4, 0x008);
    // amiibo id ? 
    memcpy(&mut out, 0x054, &internal, 0x1DC, 0x02C);
    out
}

pub struct AmiiboKeys {
    pub data: MasterKeys,
    pub tag: MasterKeys,
}
impl AmiiboKeys {
    pub fn load_keys(key: [u8; 160]) -> Result<Self, AmiitoolError> {
        let data = MasterKeys::load_key(key[0..80].try_into().unwrap())?;
        let tag  = MasterKeys::load_key(key[80..160].try_into().unwrap())?;
        Ok(AmiiboKeys {data, tag})
    }
}
impl MasterKeys {
    pub fn load_key(key: [u8; 80]) -> Result<Self, AmiitoolError> {
        let res = MasterKeys {
            hmac_key: key[0..16].try_into().expect("Fixed slice size"),
            type_string: key[16..30].try_into().expect("Fixed slice size"),
            magic_bytes_size: key[31], // 31 is intentional, i'm skipping over an unused field
            magic_bytes: key[32..48].try_into().expect("Fixed slice size"), 
            xor_pad: key[48..80].try_into().expect("Fixed slice size")
        };
        if res.magic_bytes_size > 16 {
            Err(AmiitoolError { why:  "magic bytes too big".to_string() })
        } else {
            Ok(res)
        }
    }
}
const HMAC_POS_DATA: usize = 0x8;
const HMAC_POS_TAG: usize = 0x1b4;
#[derive(Clone, Debug)]
pub struct UnverifiedAmiibo {
    data : [u8; AMIIBO_SIZE],
    intl : [u8; AMIIBO_SIZE]
}

impl UnverifiedAmiibo {
    pub fn get_checked(self) -> Result<PlainAmiibo, AmiitoolError> {
        if self.is_valid() {
            Ok(self.data.into())
        } else {
            Err(AmiitoolError { why : "Invalid Signature".to_string() })
        }
    }
    pub fn is_valid(&self) -> bool {
        self.data[HMAC_POS_DATA..HMAC_POS_DATA + 32] == self.intl[HMAC_POS_DATA..HMAC_POS_DATA + 32] 
           && self.data[HMAC_POS_TAG..HMAC_POS_TAG + 32] == self.intl[HMAC_POS_TAG..HMAC_POS_TAG + 32]
    }
    pub fn get_unchecked(self) -> PlainAmiibo {
        self.data.into()
    }
}
// legacy function
pub fn amiibo_unpack(amiibo_keys: &AmiiboKeys, amiibo: PackedAmiibo) -> Result<UnverifiedAmiibo, AmiitoolError> {
    amiibo.unpack(amiibo_keys)
}
// legacy function
pub fn amiibo_pack(amiibo_keys: &AmiiboKeys, plain_amiibo: PlainAmiibo) -> Result<PackedAmiibo, AmiitoolError> {
    plain_amiibo.pack(amiibo_keys)
}
use std::io::{BufRead, BufReader, Read};
pub fn load_keys(path: &str) -> Result<AmiiboKeys, AmiitoolError> {
    let file = std::fs::File::open(path)?;
    let mut buf = BufReader::new(file);
    let mut out = [0; 160];
    buf.read_exact(&mut out)?;
    let in_buf = buf.fill_buf()?;
    if !in_buf.is_empty() {
        Err(AmiitoolError {
            why : "not valid key file".to_string(),
        })
    } else {
        AmiiboKeys::load_keys(out)
    }
}
// legacy function
pub fn read_master_key(key: [u8; 80]) -> Result<MasterKeys, AmiitoolError> {
    MasterKeys::load_key(key)
}


use rand::Rng;

pub fn gen_amiibo_raw(amiibo_id: [u8; 8], tag_uid: &[u8]) -> Result<PlainAmiibo, AmiitoolError> {
    PlainAmiibo::generate(amiibo_id, tag_uid) 
}

pub fn gen_amiibo(key: &AmiiboKeys, amiibo_id: [u8; 8], tag_uid: &[u8]) -> Result<PackedAmiibo, AmiitoolError> {
    PackedAmiibo::generate(amiibo_id, tag_uid, key)
}

fn compute_hmac(key: [u8; 16], input: &[u8], input_offset: usize, input_len: usize) -> [u8; DRBG_OUTPUT_SIZE]  {
    let mut hmac = Hmac256::new_from_slice(&key).expect("fixed length slice");
    hmac.update(&input[len_range(input_offset, input_len)]);
    hmac.finalize().into_bytes().try_into().unwrap()
        
}
// legacy function 
pub fn read_amiibo_keys(key: [u8; 160]) -> Result<AmiiboKeys, AmiitoolError> {
    AmiiboKeys::load_keys(key)
}
/*
fn printhex(data: &[u8]) {
    for i in 0..data.len() {
        if (i % 16) > 0 {
            print!(" ");
        }
        print!("{:02X}", data[i]);
        if (i % 16) == 15 {
            print!("\n");
        }
    }
    print!("\n");
    if (data.len() % 16) != 0 {
        print!("\n");
    } 
}

*/

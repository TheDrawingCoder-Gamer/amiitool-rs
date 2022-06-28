#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn packing() {
        let keys = load_keys("key_retail.bin").unwrap(); // commiting crimes time :grin:
        // this is emitted from amiitool, which is known to produce good bins
        let sample_signed  : [u8; AMIIBO_SIZE] = std::fs::read("sample_signed.bin").unwrap().try_into().unwrap(); 
        // this is an unencrpyted file
        let sample_unsigned = std::fs::read("sample2_unsigned.bin").unwrap().try_into().unwrap();

        let packed_sample = amiibo_pack(&keys, sample_unsigned).unwrap();
        
        assert_eq!(packed_sample, sample_signed);
    }
    #[test]
    fn unpacking() {
        let keys = load_keys("key_retail.bin").unwrap();
        let sample_signed = std::fs::read("sample_signed.bin").unwrap().try_into().unwrap();
        let sample_unsigned : [u8; AMIIBO_SIZE] = std::fs::read("sample2_unsigned.bin").unwrap().try_into().unwrap();

        let unpacked_sample = amiibo_unpack(&keys, sample_signed).unwrap().get_unchecked();

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
    hmac_key: [u8; 16],
    type_string: [u8; 14],
    magic_bytes_size: u8,
    magic_bytes: [u8; 16],
    xor_pad: [u8; 32],
}
#[derive(Default,Copy, Clone,Debug)]
struct DerivedKeys {
    aes_key: [u8; 16],
    aes_iv: [u8; 16],
    hmac_key: [u8; 16],
}
#[inline]
fn len_range(start: usize, len : usize) -> std::ops::Range<usize> {
    start..start+len
}
fn memset<T:Clone>(dest: &mut [T], dest_offset: usize, data : T, len : usize) {
    dest[len_range(dest_offset, len)].fill(data);
}
fn memcpy<T:Copy>(dest: &mut [T], dest_offset: usize, source: &[T], source_offset: usize, len : usize) {
    dest[len_range(dest_offset, len)].copy_from_slice(&source[len_range(source_offset, len)])
}
fn keygen_prepare_seed(base_keys: &MasterKeys, base_seed: [u8; KEYGEN_SEED_SIZE]) -> io::Result<Vec<u8>> {
    if base_keys.magic_bytes_size > 16 {
       return Err(io::Error::new(io::ErrorKind::InvalidData,"magic byte size too big")); 
    }

    let mut cursor = Cursor::new(Vec::new());
    // this is meant to get all things
    let da_str : Vec<u8>= base_keys.type_string.iter().take_while(|x| **x != 0).copied().collect();
    // 1: Copy whole type string
    cursor.write(&da_str)?;
    // this single line fixes the entire lib. ffk;afoih
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

fn keygen_gen(base_keys: &MasterKeys, base_seed: [u8; KEYGEN_SEED_SIZE]) -> io::Result<DerivedKeys> {
    let res = keygen_prepare_seed(base_keys, base_seed)?;
    let bytes = drbg_gen_bytes(base_keys.hmac_key, &res);
    println!("{:?}", bytes);
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
    DerivedKeys { aes_key : out[0..16].try_into().unwrap(), aes_iv: out[16..32].try_into().unwrap(), hmac_key: out[32..48].try_into().unwrap() } 
}
const AMIIBO_SIZE: usize = 540;
fn amiibo_calc_seed(dump: [u8; AMIIBO_SIZE]) -> [u8; KEYGEN_SEED_SIZE] {
    let mut key: [u8; KEYGEN_SEED_SIZE] = [0; KEYGEN_SEED_SIZE];
    memcpy(&mut key, 0x00, &dump, 0x029, 0x02);
    memset(&mut key, 0x02, 0x00, 0x0E);
    memcpy(&mut key, 0x10, &dump, 0x1D4, 0x08);
    memcpy(&mut key, 0x18, &dump, 0x1D4, 0x08);
    memcpy(&mut key, 0x20, &dump, 0x1E8, 0x20);
    key
}
fn amiibo_keygen(master_keys: &MasterKeys, dump: [u8; AMIIBO_SIZE]) -> io::Result<DerivedKeys> {
    let seed = amiibo_calc_seed(dump);
    keygen_gen(master_keys, seed)
}

use aes::cipher::{KeyIvInit, StreamCipher};
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
// slightly wrong output on not real inputs
fn amiibo_cipher(derived_keys: &DerivedKeys, input: [u8; AMIIBO_SIZE], out: &mut [u8; AMIIBO_SIZE]) -> () {
    let mut cipher: Aes128Ctr =
        Aes128Ctr::new(&derived_keys.aes_key.into(), &derived_keys.aes_iv.into());

    
    cipher.apply_keystream_b2b(&input[len_range(0x2c, 0x188)], &mut out[len_range(0x2c, 0x188)]).unwrap();
    memcpy(out, 0, &input, 0, 0x8);
    // data sig NOT copied
    memcpy(out, 0x28, &input, 0x28, 0x4);
    // tag sig NOT copied
    memcpy(out, 0x1d4, &input, 0x1d4, 0x34);
    printhex(out);

}
fn amiibo_tag_to_internal(tag: [u8; AMIIBO_SIZE]) -> [u8; AMIIBO_SIZE] {
    let mut out = [0; AMIIBO_SIZE];
    memcpy(&mut out, 0x0, &tag, 0x8, 0x8);
    memcpy(&mut out, 0x8, &tag, 0x80, 0x20);
    memcpy(&mut out, 0x28, &tag, 0x10, 0x24);
    memcpy(&mut out, 0x4c, &tag, 0xa0, 0x168);
    memcpy(&mut out, 0x1b4, &tag, 0x34, 0x20);
    memcpy(&mut out, 0x1d4, &tag, 0x0, 0x8);
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
	memcpy(&mut out, 0x054, &internal, 0x1DC, 0x02C);
    out.try_into().unwrap()
}

pub struct AmiiboKeys {
    pub data: MasterKeys,
    pub tag: MasterKeys,
}
const HMAC_POS_DATA: usize = 0x8;
const HMAC_POS_TAG: usize = 0x1b4;
pub struct UnverifiedAmiibo {
    data : [u8; AMIIBO_SIZE],
    intl : [u8; AMIIBO_SIZE]
}

impl UnverifiedAmiibo {
    pub fn get_checked(self) -> io::Result<[u8; AMIIBO_SIZE]> {
        if self.data[HMAC_POS_DATA..HMAC_POS_DATA + 32] != self.intl[HMAC_POS_DATA..HMAC_POS_DATA + 32] 
           || self.data[HMAC_POS_TAG..HMAC_POS_TAG + 32] != self.intl[HMAC_POS_TAG..HMAC_POS_TAG + 32] {
            Err(io::Error::new(io::ErrorKind::Other, "Invalid Signature"))
        } else {
            Ok(self.data)
        }
    }
    pub fn get_unchecked(self) -> [u8; AMIIBO_SIZE] {
        self.data
    }
}
pub fn amiibo_unpack(amiibo_keys: &AmiiboKeys, tag: [u8; AMIIBO_SIZE]) -> io::Result<UnverifiedAmiibo> {
    // convert format
    let intl = amiibo_tag_to_internal(tag);

    // Generate keys
    let data_keys = amiibo_keygen(&amiibo_keys.data, intl).unwrap();
    let tag_keys = amiibo_keygen(&amiibo_keys.tag, intl).unwrap();

    // decrypt
    let mut plain = [0; AMIIBO_SIZE];
    amiibo_cipher(&data_keys, intl, &mut plain);
    
    // Regenerate tag HMAC. Order matters, data HMAC depends on tag HMAC.
    compute_hmac(tag_keys.hmac_key, &plain.clone(), 0x1d4, 0x34, &mut plain, HMAC_POS_TAG);

    // Regenerate data HMAC.
    compute_hmac(data_keys.hmac_key, &plain.clone(), 0x29, 0x1df, &mut plain, HMAC_POS_DATA);
    memcpy(&mut plain, 0x208, &tag, 0x208, 0x14);
    if plain[HMAC_POS_DATA..HMAC_POS_DATA + 32] != intl[HMAC_POS_DATA..HMAC_POS_DATA + 32] 
        || plain[HMAC_POS_TAG..HMAC_POS_TAG + 32] != intl[HMAC_POS_TAG..HMAC_POS_TAG + 32] {
        Err(io::Error::new(io::ErrorKind::Other, "Failed check"))
    } else {
        Ok(UnverifiedAmiibo {data: plain, intl} )
    }
}
pub fn amiibo_pack(amiibo_keys: &AmiiboKeys, plain: [u8; AMIIBO_SIZE]) -> io::Result<[u8;AMIIBO_SIZE]> {
    let mut cipher = [0; AMIIBO_SIZE];

    // generate keys
    let tag_keys = amiibo_keygen(&amiibo_keys.tag, plain)?;
    let data_keys = amiibo_keygen(&amiibo_keys.data, plain)?;
    compute_hmac(tag_keys.hmac_key, &plain, 0x1d4, 0x34, &mut cipher, HMAC_POS_TAG);
    let mut data = Vec::new();
    // data
    data.extend_from_slice(&plain[len_range(0x29, 0x18B)]);
    data.extend_from_slice(&cipher[len_range(HMAC_POS_TAG,0x20)]); // Tag HMAC
    data.extend_from_slice(&plain[len_range(0x1D4, 0x34)]); // Unknown
    compute_hmac(data_keys.hmac_key, data.as_slice(), 0, data.len(), &mut cipher, HMAC_POS_DATA);

    amiibo_cipher(&data_keys, plain, &mut cipher); 
    let mut packed = amiibo_internal_to_tag(cipher);
    
    memcpy(&mut packed, 0x208, &plain, 0x208, 0x14);
    Ok(packed)
}
use std::io::{BufRead, BufReader, Read};
pub fn load_keys(path: &str) -> std::io::Result<AmiiboKeys> {
    let file = std::fs::File::open(path)?;
    let mut buf = BufReader::new(file);
    let mut out = [0; 160];
    buf.read_exact(&mut out)?;
    let in_buf = buf.fill_buf()?;
    if !in_buf.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not valid key file",
        ))
    } else {
        let data = read_master_key(out[0..80].try_into().unwrap())?;
        let tag  = read_master_key(out[80..160].try_into().unwrap())?;
        Ok(AmiiboKeys { data, tag})
    }
}

pub fn read_master_key(key: [u8; 80]) -> io::Result<MasterKeys> {
    let res = MasterKeys {
        hmac_key: key[0..16].try_into().unwrap(),
        type_string: key[16..30].try_into().unwrap(),
        magic_bytes_size: key[31], // 31 is intentional, i'm skipping over an unused field
        magic_bytes: key[32..48].try_into().unwrap(), 
        xor_pad: key[48..80].try_into().unwrap()
    };
    if res.magic_bytes_size > 16 {
        Err(io::Error::new(io::ErrorKind::InvalidData, "magic bytes too big"))
    } else {
        Ok(res)
    }
}

pub fn read_amiibo_keys(key: [u8; 160]) -> io::Result<AmiiboKeys> {
    let data = read_master_key(key[0..80].try_into().unwrap())?;
    let tag  = read_master_key(key[80..160].try_into().unwrap())?;
    Ok(AmiiboKeys {data, tag})
}
fn compute_hmac(key: [u8; 16], input: &[u8], input_offset: usize, input_len: usize, output: &mut [u8], output_offset: usize)  {
    let mut hmac = Hmac256::new_from_slice(&key).expect("fixed length slice");
    hmac.update(&input[len_range(input_offset, input_len)]);
    output[len_range(output_offset, DRBG_OUTPUT_SIZE)].copy_from_slice(&hmac.finalize().into_bytes());
        
}

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



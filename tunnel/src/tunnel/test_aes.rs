use crypto::{aes, buffer};
use crypto::aes::KeySize;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::md5::Md5;

#[test]
fn encrypt() {

    // 计算字符串的MD5哈希值
    let mut hasher = Md5::new();
    hasher.input_str(&*String::from("855ddy1sg2nczhxh4vgl"));

    let string = hasher.result_str();
    println!("{}", string);

    let mut encryptor = aes::ecb_encryptor(KeySize::KeySize256, string.as_bytes(), PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(&[
        0x0f,
        0x2f,
        0x00,
        0x00,
        0x00,
        0x40,
        0x9f,
        0x89,
        0x0c,
        0x8f,
        0x31,
        0x90,
        0x2a,
        0xd5,
        0x06,
        0x61,
        0xe8,
        0xe4,
        0x6a,
        0xa4,
        0x34,
        0x74,
        0xb0,
        0xff,
        0xc1,
        0x3a,
        0xd4,
        0x6c,
        0x16,
        0x69,
        0x42,
        0x63,
        0xf5,
        0xb0,
        0x03,
        0x3c,
        0x52,
        0x51,
        0xbd,
        0x21,
        0x6d,
        0x87,
        0x15,
        0x17,
        0xeb,
        0x1c,
        0xf7,
        0xfe,
        0x5e,
        0xbc,
        0xd1,
        0xea,
        0x70,
        0x12,
        0x5b,
        0x8e,
        0x85,
        0x49,
        0x36,
        0x24,
        0xa5,
        0x5c,
        0x06,
        0xdb,
        0xe2,
        0x47,
        0xc4,
        0x34,
        0x19,
        0xa1,
    ]
    );
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    println!("{:#04x?}", final_result.as_slice())
}

#[test]
fn decrypt() {
    // 计算字符串的MD5哈希值
    let mut hasher = Md5::new();
    hasher.input_str(&*String::from("855ddy1sg2nczhxh4vgl"));

    let string = hasher.result_str();
    println!("{}", string);


    let encrypted_data = &[
        0xfe,
        0x04,
        0x2c,
        0xe2,
        0x6e,
        0x71,
        0x1d,
        0x3a,
        0xca,
        0x73,
        0x1d,
        0x79,
        0x9c,
        0x79,
        0x46,
        0xa5,
        0xb0,
        0xff,
        0xc1,
        0x3a,
        0xd4,
        0x6c,
        0x16,
        0x69,
        0x42,
        0x63,
        0xf5,
        0xb0,
        0x03,
        0x3c,
        0x52,
        0x51,
        0xbd,
        0x21,
        0x6d,
        0x87,
        0x15,
        0x17,
        0xeb,
        0x1c,
        0xf7,
        0xfe,
        0x5e,
        0xbc,
        0xd1,
        0xea,
        0x70,
        0x12,
        0x5b,
        0x8e,
        0x85,
        0x49,
        0x36,
        0x24,
        0xa5,
        0x5c,
        0x06,
        0xdb,
        0xe2,
        0x47,
        0xc4,
        0x34,
        0x19,
        0xa1
    ];

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    let mut decryptor = aes::ecb_decryptor(KeySize::KeySize256, string.as_bytes(), PkcsPadding);
    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    println!("{:02x?}", final_result)
}
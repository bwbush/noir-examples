use bigcurve::curves::secp521r1::{Secp521r1_Fq, Secp521r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp521r1_ecdsa;
use sha512::sha512::digest;


fn main(tbs: [u8; 822]) {

  let message_hash: [u8; 64] = digest(tbs);

  let message_hash_computed: [u8; 64] = [
    0x2c, 0xf3, 0x67, 0xa5, 0x2f, 0xa8, 0xdd, 0x43,
    0x31, 0x23, 0x2e, 0x2d, 0xed, 0xa6, 0x28, 0xaf,
    0x50, 0x9d, 0xa1, 0x21, 0xb8, 0x1e, 0xc8, 0x77,
    0xf1, 0x5d, 0x69, 0x17, 0x7a, 0xc3, 0x7e, 0x17,
    0x5c, 0x25, 0xde, 0x6c, 0x26, 0x0b, 0x74, 0x79,
    0x02, 0x37, 0x9b, 0xc8, 0x16, 0xd6, 0x80, 0xbf,
    0x0d, 0x81, 0x5d, 0xba, 0xe5, 0x2f, 0x0f, 0x00,
    0x16, 0x44, 0xb0, 0x64, 0x36, 0xd1, 0x31, 0xbe
  ];

  assert(message_hash == message_hash_computed);

  let public_key_x: Secp521r1_Fq =
    Secp521r1_Fq::from_limbs([
      0x4aa107956ca437a66f058324139059,
      0xd164821bc7b80d64d834a89b5844e6,
      0xd8329d254ca987719c5aca1d45e1ea,
      0x4ad13d83f5c8784e6fb440fd80436e,
      0x01c738196fed
    ]);
  let public_key_y: Secp521r1_Fq = 
    Secp521r1_Fq::from_limbs([
      0xd5f7794a43e200b972f86c2b444512,
      0x05b6ecca4832153c0c705616978068,
      0xa21ba4d447a50815069157d31a4b4e,
      0x4b5c70b62378cec5f7138f77351b65,
      0x018e23fd2ddc
    ]);
  
  let signature_r: Secp521r1_Fr = 
    Secp521r1_Fr::from_limbs([
      0xf0106d52bcd1a54dd73d2909cbd758,
      0xec006fc0d392daf8eec7b5e1b9b886,
      0x6662e5559a76f13281621d7d0d9c1c,
      0x721b4b2533f6168b2080ea7a71be23,
      0x01028a2c7151
    ]);
  let signature_s: Secp521r1_Fr = 
    Secp521r1_Fr::from_limbs([
      0x071c55ba613c0bc6d9fb480615a6e2,
      0x2c38a79dc23467797500886b908b50,
      0xc85c6743b8a7f7f0c4137b31edf0ab,
      0xa8eee3e52cd62563d9e445bda5486b,
      0xa8c7c3742d
    ]);
  
  let is_valid = verify_secp521r1_ecdsa(
      public_key_x,
      public_key_y,
      message_hash,
      (signature_r, signature_s)
  );

  assert(is_valid);
}

use bigcurve::curves::secp521r1::{Secp521r1_Fq, Secp521r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp521r1_ecdsa;
use sha512::sha512::digest;


// --enable-brillig-constraints-check-lookback

fn main(
  tbs: [u8; 822],
  signature_r: pub Secp521r1_Fr,
  signature_s: pub Secp521r1_Fr,
  timestamp: pub str<13>,
) {

  // The validity range starts at byte `0x82`.
  let offset: u32 = 0x82;

  // Verify that the bytes are the sequence of two UTC times.
  assert(tbs[offset] == 0x1e);
  assert(tbs[offset + 1] == 0x17);
  assert(tbs[offset + 2] == 0x0d);
  assert(tbs[offset + 16] == 0x17);
  assert(tbs[offset + 17] == 0x0d);

  // Compare lexicalographically.
  let timestamp_bytes = timestamp.as_bytes();
  let mut notDone: bool = true;
  for i in 0..11 {
    if notDone {
      let lb = tbs[offset + 3 + i];
      let x = timestamp_bytes[i];
      let ub = tbs[offset + 18 + i];
      assert(x >= lb);
      assert(x <= ub);
      if (x > lb) & (x < ub) {
        notDone = false;
      }
    }
  }

  // Enforce the timezone `Z`.
  assert(timestamp_bytes[12] == 0x5a);
  assert(tbs[offset + 15] == 0x5a);
  assert(tbs[offset + 30] == 0x5a);

  // Compute the hash of the message.
  let message_hash: [u8; 64] = digest(tbs);

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
  
//let signature_r: Secp521r1_Fr = 
//  Secp521r1_Fr::from_limbs([
//    0xf0106d52bcd1a54dd73d2909cbd758,
//    0xec006fc0d392daf8eec7b5e1b9b886,
//    0x6662e5559a76f13281621d7d0d9c1c,
//    0x721b4b2533f6168b2080ea7a71be23,
//    0x01028a2c7151
//  ]);
//let signature_s: Secp521r1_Fr = 
//  Secp521r1_Fr::from_limbs([
//    0x071c55ba613c0bc6d9fb480615a6e2,
//    0x2c38a79dc23467797500886b908b50,
//    0xc85c6743b8a7f7f0c4137b31edf0ab,
//    0xa8eee3e52cd62563d9e445bda5486b,
//    0xa8c7c3742d
//  ]);
  
  // FIXME: Sadly, `verify_secp521r1_ecdsa` is an unconstrained function.
  let is_valid = verify_secp521r1_ecdsa(
    public_key_x,
    public_key_y,
    message_hash,
    (signature_r, signature_s)
  );
  assert(is_valid);

}

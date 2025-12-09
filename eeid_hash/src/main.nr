use sha512::sha512::digest;


fn main(
  tbs: [u8; 822],
  timestamp: pub str<13>,
) -> pub [u8; 64] {

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
  let message_hash_computed: [u8; 64] = digest(tbs);

  // Return the hash as public output.
  message_hash_computed

}


fn main(x: Field, y: pub Field, expected_hash: pub Field) {
    let hash = std::hash::pedersen_hash([x, y]);
    assert_eq(hash, expected_hash);
}


#[test]
fn test_main() {
//  println(std::hash::pedersen_hash([1, 2]));
    main(1, 2, 0x17cb544f4d22abbae88f69c706f21367d7925abb131a13836745714dc896c150);
}


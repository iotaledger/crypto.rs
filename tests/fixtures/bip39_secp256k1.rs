[
    // https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-secp256k1
    TestVector {
        seed: "000102030405060708090a0b0c0d0e0f",
        master_chain_code: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        master_private_key: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        chains: vec![
          TestChain {
              chain: Chain::empty(),
              chain_code: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
              private_key: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
          },
          TestChain {
              chain: Chain::from_u32_hardened(vec![0]),
              chain_code: "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
              private_key: "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
          },
          TestChain {
              chain: Chain::from_u32_hardened(vec![0]),
              chain_code: "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
              private_key: "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
          },
          TestChain {
              chain: Chain::from_u32(vec![0 | Segment::HARDEN_MASK, 1]),
              chain_code: "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
              private_key: "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
          },
          TestChain {
              chain: Chain::from_u32(vec![0 | Segment::HARDEN_MASK, 1, 2 | Segment::HARDEN_MASK]),
              chain_code: "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
              private_key: "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
          },
          TestChain {
              chain: Chain::from_u32(vec![0 | Segment::HARDEN_MASK, 1, 2 | Segment::HARDEN_MASK, 2]),
              chain_code: "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
              private_key: "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
          },
          TestChain {
              chain: Chain::from_u32(vec![0 | Segment::HARDEN_MASK, 1, 2 | Segment::HARDEN_MASK, 2, 1000000000]),
              chain_code: "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
              private_key: "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
          },
        ]
    }
]
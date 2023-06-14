[
    // https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-secp256k1
    TestVector {
        seed: "000102030405060708090a0b0c0d0e0f",
        master_chain_code: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        master_private_key: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        chains: vec![
            TestChain {
                chain: vec![],
                chain_code: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                private_key: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            },
            TestChain {
                chain: vec![0.harden().into()],
                chain_code: "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                private_key: "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            },
            TestChain {
                chain: vec![0.harden().into(), 1],
                chain_code: "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                private_key: "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            },
            TestChain {
                chain: vec![0.harden().into(), 1, 2.harden().into()],
                chain_code: "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                private_key: "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            },
            TestChain {
                chain: vec![0.harden().into(), 1, 2.harden().into(), 2],
                chain_code: "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                private_key: "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
            },
            TestChain {
                chain: vec![0.harden().into(), 1, 2.harden().into(), 2, 1000000000],
                chain_code: "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                private_key: "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
            },
        ],
    },
    // https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-secp256k1
    TestVector {
        seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        master_chain_code: "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
        master_private_key: "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
        chains: vec![
            TestChain {
                chain: vec![],
                chain_code: "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                private_key: "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
            },
            TestChain {
                chain: vec![0],
                chain_code: "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                private_key: "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
            },
            TestChain {
                chain: vec![0, 2147483647.harden().into()],
                chain_code: "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                private_key: "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
            },
            TestChain {
                chain: vec![0, 2147483647.harden().into(), 1],
                chain_code: "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                private_key: "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
            },
            TestChain {
                chain: vec![0, 2147483647.harden().into(), 1, 2147483646.harden().into()],
                chain_code: "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                private_key: "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
            },
            TestChain {
                chain: vec![0, 2147483647.harden().into(), 1, 2147483646.harden().into(), 2],
                chain_code: "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                private_key: "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
            },
        ],
    }
]

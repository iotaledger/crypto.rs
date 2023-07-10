[
    // Keccak-256 is not standard function, hence there's no standard test vectors
    // https://github.com/debris/tiny-keccak/blob/master/tests/keccak.rs
    TestVector {
        msg: "",
        digest: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    },
    TestVector {
        msg: "0102030405",
        digest: "7d87c5ea75f7378bb701e404c50639161af3eff66293e9f375b5f17eb50476f4",
    },
]

var crypto = require('../.')
console.log(crypto)
console.log('sync:  ', crypto.random(128))
console.log('edgen: ', crypto.ed25519Generate())

// const pk = crypto.sync.ed25519.generate()
// console.log('ed25519:  ', pk)

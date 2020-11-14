var crypto = require('../.')

console.log('sync:  ', crypto.sync.random(64))
const pk = crypto.sync.ed25519.generate()
console.log('ed25519:  ', pk)

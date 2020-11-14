var crypto = require('../lib')

console.log('syncRandom:  ', crypto.syncRandom(64))
crypto.asyncRandom(64).then(v => {console.log('asyncRandom: ', v)})
console.log('sync:  ', crypto.sync.random(64))
console.log('ed25519:  ', crypto.sync.random(64))

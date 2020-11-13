var crypto = require('../.')

console.log('syncRandom:  ', crypto.syncRandom(64))
crypto.asyncRandom(64).then(v => {console.log('asyncRandom: ', v)})

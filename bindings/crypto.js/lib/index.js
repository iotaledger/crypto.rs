var addon = require('../native');

module.exports = {
    asyncRandom(size = 16) {
        return new Promise((resolve, reject) => {
            addon.asyncRandom(size, (err, res) => {
                if (err) {
                  reject(err)
                } else {
                  resolve(res)
                }
              })
        })
    },
    syncRandom(size = 16) {
        try {
            return res = addon.syncRandom(size)
        } catch (e) {
            throw new Error(e)
        }
    }
  }

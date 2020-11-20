var addon = require('../native');

let commandTemplate = {
    feature: '',
    function: '',
    payload: '',
    size: 0,
    returns: ''
}

module.exports = {
    random (size = 16) {
        try {
            return res = addon.random(size)
        } catch (e) {
            throw new Error(e)
        }
    },
    ed25519Generate () {
        try {
            return res = addon.ed25519Generate()
        } catch (e) {
            throw new Error(e)
        }
    },
    sync: {
        /**
         * @param {Number} size 
         * @returns {Array}
         */
        random(size = 16) {
            let cmd = {
                ...commandTemplate,
                feature: 'rand',
                function: 'fill',
                size: size,
            }
            try {
                return res = addon.sync(cmd)
            } catch (e) {
                throw new Error(e)
            }
        },
        ed25519: {
            generate () {
                let cmd = {
                    // create keypair
                    ...commandTemplate,
                    feature: 'ed25519',
                    function: 'generate',
                    returns: 'string'
                }
                try {
                    return res = addon.sync(cmd)
                } catch (e) {
                    throw new Error(e)
                }
            },
            verify () {
    
            },
            create () {
    
            }
        },
    }
  }

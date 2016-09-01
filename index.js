'use strict';

const {toCYON} = require('./lib/cyon');
const objc = require('./lib/objc');
const types = require('./lib/types');

module.exports = {
  register() {
    types.register();
    objc.register();
  },
  add(name, details) {
    return types.add(name, details);
  },
  lookup(name) {
    return objc.lookup(name);
  },
  complete(prefix) {
    return objc.complete(prefix);
  },
  toCYON(value) {
    return toCYON(value);
  }
};

'use strict';

const objc = require('./lib/objc');
const types = require('./lib/types');

module.exports = {
  register() {
    types.register();
    objc.register();
  }
};

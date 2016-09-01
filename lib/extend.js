'use strict';

module.exports = function (klass, superKlass) {
  const Surrogate = function () {
    this.constructor = klass;
  };
  Surrogate.prototype = superKlass.prototype;
  klass.prototype = new Surrogate();
};

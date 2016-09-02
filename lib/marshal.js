'use strict';

let parsePropertyIndex;

if (Script.runtime === 'DUK') {
  parsePropertyIndex = function (property) {
    return (typeof property === 'number') ? property : null;
  };
} else {
  parsePropertyIndex = function (property) {
    if (typeof property !== 'string')
      return null;
    const index = parseInt(property);
    return !isNaN(index) ? index : null;
  };
}

module.exports = {
  parsePropertyIndex: parsePropertyIndex
};

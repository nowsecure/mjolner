module.exports = {
  toCYON: toCYON
};

function toCYON(value) {
  if (value === undefined) {
    return 'undefined';
  } else if (value === null) {
    return 'null';
  } else {
    const type = typeof value;
    if (type === 'boolean') {
      return value ? 'true' : 'false';
    } else if (type === 'number') {
      return '' + value;
    } else if (type === 'string') {
      return stringify(value);
    } else if ('toCYON' in value) {
      return value.toCYON();
    } else if (value instanceof Array) {
      return ['[', value.map(element => toCYON(element)), ']'].join('');
    } else {
      return ['{', Object.keys(value).map(key => {
        return [key, ':', toCYON(value[key])].join('');
      }).join(','), '}'].join('');
    }
  }
}

function stringify(value) {
  // TODO: prettify
  return '"' + value + '"';
}

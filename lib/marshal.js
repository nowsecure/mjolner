module.exports = {
  parsePropertyIndex: parsePropertyIndex
};

function parsePropertyIndex(property) {
  const type = typeof property;
  if (type === 'number')
    return property;
  else if (type !== 'string')
    return null;
  const index = parseInt(property);
  return !isNaN(index) ? index : null;
}

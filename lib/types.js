'use strict';

const extend = require('./extend');
const objectAssign = require('object-assign');
const {parsePropertyIndex} = require('./marshal');
const {toCYON} = require('./cyon');

const CyBridgeVoid = 1;
const CyBridgeHold = 2;
const CyBridgeType = 3;

const pointerSize = Process.pointerSize;

const PARAMS = Symbol('params');
const PRIV = Symbol('priv');

let voidType = null;

const strlen = new NativeFunction(Module.findExportByName(null, 'strlen'), 'int', ['pointer']);

module.exports = {
  register() {
    global.Type = Type;

    global.typeid = function (value) {
      return value.$cyt;
    };

    voidType = makeType({
      name: 'void',
      nativeType: 'void',
      size: 0,
      alignment: 1,
      constant: false
    });

    const longBits = (pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;
    const longSize = longBits / 8;

    [
      ['bool', 'bool', 'bool', 'U8', 1, false],
      ['char', 'char', 'char', 'U8', 1, 0],
      ['schar', 'signed char', 'char', 'S8', 1, 0],
      ['uchar', 'unsigned char', 'uchar', 'U8', 1, 0],

      ['short', 'short', 'int16', 'S16', 2, 0],
      ['int', 'int', 'int32', 'S32', 4, 0],
      ['long', 'long', 'int' + longBits, 'S' + longBits, longSize, 0],
      ['longlong', 'long long', 'int64', 'S64', 8, 0],

      ['ushort', 'unsigned short', 'uint16', 'U16', 2, 0],
      ['uint', 'unsigned int', 'uint32', 'U32', 4, 0],
      ['ulong', 'unsigned long', 'uint' + longBits, 'U' + longBits, longSize, 0],
      ['ulonglong', 'unsigned long long', 'uint64', 'U64', 8, 0],

      ['float', 'float', 'float', 'Float', 4, 0],
      ['double', 'double', 'double', 'Double', 8, 0],
      ['longdouble', 'long double', 'double', 'Double', 8, 0],
    ]
    .forEach(spec => {
      const [alias, name, nativeType, memoryType, size, defaultValue] = spec;
      global[alias] = makeType({
        name: name,
        nativeType: nativeType,
        size: size,
        alignment: size,
        constant: false,
        defaultValue: defaultValue,
        read: Memory['read' + memoryType],
        write: Memory['write' + memoryType]
      });
    });

    global.RTLD_DEFAULT = ptr('-2');
    const _dlsym = new NativeFunction(Module.findExportByName(null, 'dlsym'), 'pointer', ['pointer', 'pointer']);
    global.dlsym = function (handle, symbol) {
      const symbolStr = Memory.allocUtf8String(symbol);
      const address = _dlsym(handle, symbolStr);
      if (address.isNull())
        return null;
      return new PointerValue(voidType.pointerTo(), address, symbol);
    };
    Object.defineProperty(global.dlsym, 'toCYON', {
      enumerable: false,
      writable: false,
      value() {
        return '(extern "C" void *dlsym(void *, char *))';
      }
    });
  },
  add(name, details) {
    const {code, flags} = details;

    let placeholder;
    if (flags == CyBridgeType) {
      placeholder = cloneType(voidType, {});
      global[name] = placeholder;
    }

    let value = (1, eval)(code);

    if (flags === CyBridgeType) {
      const params = objectAssign({}, value[PARAMS]);
      const vfuncs = params.$vfuncs;
      Object.keys(vfuncs).forEach(name => {
        params[name] = vfuncs[name].bind(placeholder);
      });
      params.$cache = {};
      placeholder[PARAMS] = params;
      value = placeholder;
    } else if (flags === CyBridgeHold) {
      global[name] = value;
    }

    return value;
  },
  makeType: makeType,
  PointerValue: PointerValue
};

function makeType(params) {
  const type = function (value) {
    const {size, defaultValue, cast, write} = type[PARAMS];

    if (value === undefined)
      value = defaultValue;

    const isConstructorCall = this && this.constructor === type;
    if (!isConstructorCall)
      return (cast !== undefined) ? cast(value) : value;

    const typePtr = type.pointerTo();
    const data = new PointerValue(typePtr, Memory.alloc(size));
    write(data, value);
    return typePtr(data);
  };

  const vfuncs = {};
  [
    ['cast'],
    ['toNative'],
    ['read'],
    ['write'],
    ['toCYON', typeToCYON]
  ].forEach(([name, defaultValue]) => {
    const vfunc = params[name] || defaultValue;
    if (vfunc !== undefined) {
      vfuncs[name] = vfunc;
      params[name] = vfunc.bind(type);
    }
  });
  params.$vfuncs = vfuncs;
  params.$cache = {};

  Object.setPrototypeOf(type, Type.prototype);

  type[PARAMS] = params;

  return type;
}

function cloneType(type, params) {
  const sourceParams = type[PARAMS];
  return makeType(objectAssign({}, sourceParams, sourceParams.$vfuncs, params));
}

function Type() {
  const args = Array.from(arguments);
  const numArgs = args.length;
  if (numArgs === 1 && args[0] === 'v')
    return voidType;
  else if (numArgs === 2)
    return makeStruct(...args);
  else
    throw new Error('Not yet implemented');
}

extend(Type, Function);

Object.defineProperties(Type.prototype, {
  withName: {
    enumerable: false,
    writable: false,
    value(name) {
      const thisName = this[PARAMS].name;
      return cloneType(this, {
        name: (thisName === 'struct' || thisName.indexOf('struct ') === 0) ? 'struct ' + name : name
      });
    }
  },
  constant: {
    enumerable: false,
    writable: false,
    value() {
      const params = this[PARAMS];

      if (params.constant)
        return this;

      const cache = params.$cache;
      let constantType = cache.constantType;
      if (constantType === undefined) {
        constantType = cloneType(this, {
          name: params.name + ' const',
          constant: true
        });
        cache.constantType = constantType;
      }
      return constantType;
    }
  },
  pointerTo: {
    enumerable: false,
    writable: false,
    value() {
      const params = this[PARAMS];

      const cache = params.$cache;
      let pointerType = cache.pointerType;
      if (pointerType === undefined) {
        pointerType = makePointer(this);
        cache.pointerType = pointerType;
      }
      return pointerType;
    }
  },
  arrayOf: {
    enumerable: false,
    writable: false,
    value(length) {
      return makeArray(this, length);
    }
  },
  functionWith: {
    enumerable: false,
    writable: false,
    value() {
      return makeFunction(this, Array.from(arguments));
    }
  },
  toCYON: {
    enumerable: false,
    writable: false,
    value() {
      return this[PARAMS].toCYON();
    }
  }
});

function typeToCYON() {
  return `(typedef ${this[PARAMS].name})`;
}

function makePointer(target) {
  const targetName = target[PARAMS].name;
  const spacing = (targetName.lastIndexOf(' const') === targetName.length - 6) ? '' : ' ';
  const name = [targetName, spacing, '*'].join('');

  return makeType({
    name: name,
    nativeType: 'pointer',
    size: pointerSize,
    alignment: pointerSize,
    defaultValue: null,
    read: readPointer,
    write: writePointer,
    cast: castPointer,
    toNative: toNativePointer,
    target: target
  });
}

function readPointer(pointer) {
  const address = Memory.readPointer(pointer);
  if (address.isNull())
    return null;
  return new PointerValue(this, address);
}

function writePointer(pointer, value) {
  Memory.writePointer(pointer, toNativePointer(value));
}

function castPointer(value) {
  if (value instanceof PointerValue) {
    const {address, symbol} = value[PRIV];
    return new PointerValue(this, address, symbol);
  } else if (value === null || (value instanceof NativePointer && value.isNull())) {
    return null;
  } else if (typeof value === 'string' && isStringType(this[PARAMS].target[PARAMS].name)) {
    return new PointerValue(this, Memory.allocUtf8String(value));
  }

  if (!(value instanceof NativePointer))
    value = ptr(value);

  return new PointerValue(this, value);
}

function toNativePointer(value) {
  if (value instanceof PointerValue)
    return value[PRIV].address;
  else if (value instanceof NativePointer)
    return value;
  else if (value === null)
    return NULL;
  else if (typeof value === 'string')
    return Memory.allocUtf8String(value);
  else
    return ptr(value);
}

function PointerValue(type, address, symbol) {
  const targetParams = type[PARAMS].target[PARAMS];

  this[PRIV] = {
    type: type,
    address: address,
    targetParams: targetParams,
    symbol: symbol
  };

  const isString = isStringType(targetParams.name);
  if (isString)
    Object.setPrototypeOf(this, StringPointerValue.prototype);

  return new Proxy(this, {
    has(target, property) {
      if (parsePropertyIndex(property) !== null)
        return true;
      else if (isString && property === 'length')
        return true;
      else
        return (property in target);
    },
    get(target, property, receiver) {
      const index = parsePropertyIndex(property);
      if (index !== null)
        return new PointerValue(type, address.add(index)).$cyi;
      else if (isString && property === 'length')
        return strlen(address);
      else
        return target[property];
    },
    set(target, property, value, receiver) {
      const index = parsePropertyIndex(property);
      if (index === null) {
        target[property] = value;
        return true;
      }

      new PointerValue(type, address.add(index)).$cyi = value;
      return true;
    },
    ownKeys(target) {
      return [];
    },
    getOwnPropertyDescriptor(target, property) {
      return {
        writable: true,
        configurable: true,
        enumerable: true
      };
    },
  });
}

Object.defineProperties(PointerValue.prototype, {
  handle: {
    enumerable: false,
    get() {
      return this[PRIV].address;
    }
  },
  $cyt: {
    enumerable: false,
    get() {
      return this[PRIV].type;
    }
  },
  $cyi: {
    enumerable: false,
    get() {
      const {targetParams} = this[PRIV];
      const {read} = targetParams;
      if (read === undefined)
        throw new Error('Cannot read from ' + targetParams.name);
      return read(this);
    },
    set(v) {
      const {targetParams} = this[PRIV];
      const {write} = targetParams;
      if (write === undefined)
        throw new Error('Cannot write to ' + targetParams.name);
      write(this, v);
    }
  },
  toCYON: {
    enumerable: false,
    writable: false,
    value() {
      const {address, targetParams} = this[PRIV];
      const {name, read} = targetParams;
      if (address.isNull())
        return null;
      else if (read !== undefined)
        return '&' + toCYON(this.$cyi);
      else
        return '(typedef void*)(' + address + ')';
    }
  }
});

function StringPointerValue() {
}

extend(StringPointerValue, String);

Object.defineProperties(StringPointerValue.prototype, {
  handle: {
    enumerable: false,
    get() {
      return this[PRIV].address;
    }
  },
  $cyt: {
    enumerable: false,
    get() {
      return this[PRIV].type;
    }
  },
  $cyi: {
    enumerable: false,
    get() {
      const priv = this[PRIV];
      return readChar(priv.address);
    },
    set(v) {
      const {targetParams} = this[PRIV];
      const {write} = targetParams;
      if (write === undefined)
        throw new Error('Cannot write to ' + targetParams.name);
      if (typeof v === 'string')
        v = v.charCodeAt(0);
      write(this, v);
    }
  },
  toCYON: {
    enumerable: false,
    writable: false,
    value() {
      const {address} = this[PRIV];
      if (address.isNull())
        return null;
      else
        return '&"' + readCString(address) + '"';
    }
  },
  toString: {
    enumerable: true,
    writable: false,
    value() {
      const {address} = this[PRIV];
      if (address.isNull())
        return null;
      else
        return readCString(address);
    }
  }
});

function isStringType(name) {
  return name === 'char' || name === 'char const';
}

function readCString(address) {
  const length = strlen(address);
  const bytes = new Uint8Array(Memory.readByteArray(address, length));
  const result = [];
  for (let i = 0; i !== length; i++) {
    const v = bytes[i];
    const c = (v <= 0x7f) ? String.fromCharCode(v) : ('\\x' + v.toString(16));
    result.push(c);
  }
  return result.join('');
}

function readChar(address) {
  const v = Memory.readU8(address);
  if (v == 0)
    return '\\0';
  return (v <= 0x7f) ? String.fromCharCode(v) : ('\\x' + v.toString(16));
}

function makeArray(elementType, length) {
  const elementTypeParams = elementType[PARAMS];

  const defaultValue = [];
  const elementDefaultValue = elementTypeParams.defaultValue;
  for (let i = 0; i !== length; i++) {
    defaultValue.push(elementDefaultValue);
  }

  return makeType({
    name: `${elementTypeParams.name}[${length}]`,
    nativeType: 'pointer',
    size: length * elementTypeParams.size,
    alignment: elementTypeParams.alignment,
    defaultValue: defaultValue,
    read: readArray,
    write: writeArray,
    cast: castArray,
    elementType: elementType,
    length: length
  });
}

function readArray(pointer) {
  return new ArrayValue(this, pointer);
}

function writeArray(pointer, value) {
  const target = new ArrayValue(this, pointer);
  const source = castArray.call(this, value);
  const length = source.length;
  for (let i = 0; i !== length; i++)
    target[i] = source[i];
}

function castArray(value) {
  if (value instanceof ArrayValue)
    return value;

  const {size, elementType, length} = this[PARAMS];
  const elementTypePtr = elementType.pointerTo();

  let address;
  if (value instanceof PointerValue) {
    address = value.handle;
  } else if (value instanceof NativePointer) {
    address = value;
  } else if (value instanceof Array) {
    if (value.length !== length)
      throw new Error('Invalid array length');

    address = Memory.alloc(size);

    const elementSize = elementType[PARAMS].size;
    value.forEach((element, index) => {
      elementTypePtr(address.add(index * elementSize)).$cyi = element;
    });
  } else {
    throw new Error('Expected a pointer or an array');
  }

  return new ArrayValue(this, new PointerValue(elementTypePtr, address));
}

function ArrayValue(type, pointer) {
  const {elementType, length} = type[PARAMS];
  const elementSize = elementType[PARAMS].size;
  const elementTypePtr = elementType.pointerTo();
  const address = pointer.handle;

  this[PRIV] = {
    type: type,
    address: address
  };

  return new Proxy(this, {
    has(target, property) {
      if (resolveElementIndex(property) !== null)
        return true;
      else
        return (property in target);
    },
    get(target, property, receiver) {
      if (property === 'length')
        return length;
      else if (property === '$cyt')
        return type;

      const index = resolveElementIndex(property);
      if (index === null)
        return target[property];

      return elementTypePtr(address.add(index * elementSize)).$cyi;
    },
    set(target, property, value, receiver) {
      const index = resolveElementIndex(property);
      if (index === null) {
        target[property] = value;
        return true;
      }

      elementTypePtr(address.add(index * elementSize)).$cyi = value;
      return true;
    },
    ownKeys(target) {
      return [];
    },
    getOwnPropertyDescriptor(target, property) {
      return {
        writable: true,
        configurable: true,
        enumerable: true
      };
    },
  });

  function resolveElementIndex(identifier) {
    const index = parsePropertyIndex(identifier);
    if (index === null)
      return null;
    else if (index < 0 || index >= length)
      return null;
    return index;
  }
}

extend(ArrayValue, Array);

Object.defineProperties(ArrayValue.prototype, {
  handle: {
    enumerable: false,
    get() {
      return this[PRIV].address;
    }
  },
  $cyt: {
    enumerable: false,
    get() {
      return this[PRIV].type;
    }
  }
});

function makeStruct(fieldTypes, fieldNames) {
  const fieldTypeParams = fieldTypes.map(t => t[PARAMS]);

  const nativeType = fieldTypeParams.map(p => p.nativeType);
  const [fieldIndexes, fieldSpecs, size] = fieldTypes.reduce(([indexes, specs, offset], type, index) => {
    const p = type[PARAMS];

    const name = fieldNames[index];
    indexes[name] = index;
    specs.push([index, offset, name, type.pointerTo()[PARAMS], type[PARAMS]]);

    const alignment = p.alignment;

    const remainder = offset % alignment;
    if (remainder !== 0)
      offset += alignment - remainder;

    offset += p.size;

    return [indexes, specs, offset];
  }, [{}, [], 0]);
  const alignment = (fieldTypeParams.length > 0) ? fieldTypeParams[0].alignment : 1;
  const defaultValue = fieldTypeParams.map(p => p.defaultValue);

  return makeType({
    name: 'struct',
    nativeType: nativeType,
    size: size,
    alignment: alignment,
    defaultValue: defaultValue,
    read: readStruct,
    write: writeStruct,
    cast: castStruct,
    toNative: toNativeStruct,
    toCYON: structToCYON,
    fieldSpecs: fieldSpecs,
    fieldIndexes: fieldIndexes
  });
}

function readStruct(pointer) {
  return new StructValue(this, null, pointer);
}

function writeStruct(pointer, value) {
  const target = new StructValue(this, null, pointer);
  const source = castStruct.call(this, value);
  const numFields = this[PARAMS].fieldSpecs.length;
  for (let i = 0; i !== numFields; i++)
    target[i] = source[i];
}

function castStruct(value) {
  if (value instanceof StructValue)
    return value;

  let fields;
  const {fieldSpecs} = this[PARAMS];
  if (value instanceof Array) {
    if (value.length !== fieldSpecs.length)
      throw new Error('Invalid struct');
    fields = value.map((element, index) => {
      const [, , , , {cast}] = fieldSpecs[index];
      return (cast !== undefined) ? cast(element) : element;
    });
  } else if (typeof value === 'object' && value !== null) {
    return castStruct.call(this, fieldSpecs.map(([, , name]) => value[name]));
  } else {
    throw new Error('Expected a struct');
  }

  return new StructValue(this, fields, null);
}

function toNativeStruct(value) {
  const struct = castStruct.call(this, value);

  const {fieldSpecs} = this[PARAMS];
  return fieldSpecs.map((spec, index) => {
    const [, , , , {toNative}] = spec;
    return toNative(struct[index]);
  });
}

function structToCYON() {
  const fields = this[PARAMS].fieldSpecs.map(([, , name, , typeParams]) => [typeParams.name, name].join(' '));
  return `(typedef struct {
    ${fields.join(';\n    ')};
})`;
}

function StructValue(type, values, pointer) {
  const {fieldSpecs, fieldIndexes} = type[PARAMS];
  const address = (pointer !== null) ? pointer.handle : null;
  let cachedOwnKeys = null;

  return new Proxy(this, {
    has(target, property) {
      if (resolveField(property) !== null)
        return true;
      else
        return (property in target);
    },
    get(target, property, receiver) {
      if (property === '$cyt')
        return type;

      const field = resolveField(property);
      if (field === null)
        return target[property];

      if (values !== null) {
        const [index] = field;
        return values[index];
      } else {
        const [, offset, , {cast}, {read}] = field;
        return read(cast(address.add(offset)));
      }
    },
    set(target, property, value, receiver) {
      const field = resolveField(property);
      if (field === null) {
        target[property] = value;
        return true;
      }

      if (values !== null) {
        const [index, , , , {cast}] = field;
        values[index] = cast(value);
      } else {
        const [, offset, , {cast}, {write}] = field;
        write(cast(address.add(offset)), value);
      }
      return true;
    },
    ownKeys(target) {
      if (cachedOwnKeys === null) {
        cachedOwnKeys = fieldSpecs.map(([ , , name]) => name);
        // Duktape does not support getOwnPropertyDescriptor yet and checks the target instead:
        cachedOwnKeys.forEach(key => target[key] = true);
      }
      return cachedOwnKeys;
    },
    getOwnPropertyDescriptor(target, property) {
      return {
        writable: true,
        configurable: true,
        enumerable: true
      };
    },
  });

  function resolveField(identifier) {
    let index = parsePropertyIndex(identifier);
    if (index === null)
      index = fieldIndexes[identifier];
    const spec = fieldSpecs[index];
    return (spec !== undefined) ? spec : null;
  }
}

function makeFunction(retType, argTypes) {
  return makeType({
    name: 'function',
    nativeType: 'pointer',
    size: pointerSize,
    alignment: pointerSize,
    defaultValue: null,
    read: castFunction,
    cast: castFunction,
    toCYON: functionToCYON,
    retType: retType,
    argTypes: argTypes
  });
}

function castFunction(value) {
  if (value === null)
    return null;

  if (typeof value === 'function' && !(value instanceof NativePointer))
    return castToNativeCallback.call(this, value);
  else
    return castToNativeFunction.call(this, value);
}

function castToNativeFunction(value) {
  const type = this;
  const {retType, argTypes} = type[PARAMS];
  const retTypeParams = retType[PARAMS];
  const argTypeParams = argTypes.map(t => t[PARAMS]);

  const impl = new NativeFunction(value, retTypeParams.nativeType, argTypeParams.map(p => p.nativeType));

  const retCast = retTypeParams.cast;
  const argToNative = argTypeParams.map(p => p.toNative);

  const argNames = argTypes.map((_, index) => 'a' + index);
  let retConversionLeft, retConversionRight;
  if (retCast !== undefined) {
    retConversionLeft = 'retCast(';
    retConversionRight = ')';
  } else {
    retConversionLeft = '';
    retConversionRight = '';
  }
  const argConversions = argToNative.map((toNative, index) => (toNative !== undefined) ? `argToNative[${index}](${argNames[index]})` : argNames[index]);
  const numArgsRequired = argTypes.length;

  const wrapperCode = `var w = function (${argNames.join(', ')}) {
    var numArgsProvided = arguments.length;
    if (numArgsProvided < numArgsRequired)
      throw new Error('insufficient number of arguments to ffi function');
    else if (numArgsProvided > numArgsRequired)
      throw new Error('exorbitant number of arguments to ffi function');
    return ${retConversionLeft}impl(${argConversions.join(', ')})${retConversionRight};
  }; w;`;

  const wrapper = eval(wrapperCode);

  wrapper[PRIV] = {
    type: type,
    address: value
  };

  Object.setPrototypeOf(wrapper, NativeFunctionValue.prototype);

  return wrapper;
}

function NativeFunctionValue() {
}

extend(NativeFunctionValue, Function);

Object.defineProperties(NativeFunctionValue.prototype, {
  handle: {
    enumerable: false,
    get() {
      return this[PRIV].address.handle;
    }
  },
  $cyt: {
    enumerable: false,
    get() {
      return this[PRIV].type;
    }
  },
  toCYON: {
    enumerable: false,
    writable: false,
    value() {
      const {type, address} = this[PRIV];
      const {retType, argTypes} = type[PARAMS];
      let retTypeDecl = retType[PARAMS].name;
      if (retTypeDecl.indexOf(' ') === -1)
        retTypeDecl += ' ';
      return `(extern "C" ${retTypeDecl}${address[PRIV].symbol || ''}(${argTypes.map(t => t[PARAMS].name).join(', ')}))`;
    }
  }
});

function castToNativeCallback(callback) {
  const type = this;
  const {retType, argTypes} = type[PARAMS];
  const retTypeParams = retType[PARAMS];
  const argTypeParams = argTypes.map(t => t[PARAMS]);

  const retToNative = retTypeParams.toNative;
  const argCast = argTypeParams.map(p => p.cast);

  const argNames = argTypes.map((_, index) => 'a' + index);
  let retConversionLeft, retConversionRight;
  if (retToNative !== undefined) {
    retConversionLeft = 'retToNative(';
    retConversionRight = ')';
  } else {
    retConversionLeft = '';
    retConversionRight = '';
  }
  const argConversions = argCast.map((cast, index) => (cast !== undefined) ? `argCast[${index}](${argNames[index]})` : argNames[index]);

  const wrapperCode = `var w = function (${argNames.join(', ')}) {
    return ${retConversionLeft}callback(${argConversions.join(', ')})${retConversionRight};
  }; w;`;

  const wrapper = eval(wrapperCode);

  const impl = new NativeCallback(wrapper, retTypeParams.nativeType, argTypeParams.map(p => p.nativeType));

  impl[PRIV] = {
    type: type
  };

  Object.setPrototypeOf(impl, NativeCallbackValue.prototype);

  return impl;
}

function NativeCallbackValue() {
}

extend(NativeCallbackValue, NativeCallback);

Object.defineProperties(NativeCallbackValue.prototype, {
  $cyt: {
    enumerable: false,
    get() {
      return this[PRIV].type;
    }
  },
  toCYON: {
    enumerable: false,
    writable: false,
    value() {
      const {type} = this[PRIV];
      const {retType, argTypes} = type[PARAMS];
      let retTypeDecl = retType[PARAMS].name;
      if (retTypeDecl.indexOf(' ') === -1)
        retTypeDecl += ' ';
      return `(extern "C" ${retTypeDecl}${this.toString(10)}(${argTypes.map(t => t[PARAMS].name).join(', ')}))`;
    }
  }
});

function functionToCYON() {
  const {retType, argTypes} = this[PARAMS];

  let retTypeDecl = retType[PARAMS].name;
  if (retTypeDecl.indexOf(' ') === -1)
    retTypeDecl += ' ';
  return `(typedef ${retTypeDecl}(${argTypes.map(t => t[PARAMS].name).join(', ')}))`;
}

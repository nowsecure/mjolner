'use strict';

const extend = require('./extend');
const {makeType, PointerValue} = require('./types');

const pointerSize = Process.pointerSize;

const PRIV = Symbol('priv');

let classType = null;
let objectType = null;
let selectorType = null;

let singularTypeById = null;

let cachedNSString = null;
let cachedNSStringCtor = null;
let cachedNSNumber = null;
let cachedNSNumberCtor = null;

let cyonConverters = null;

let free = null;

module.exports = {
  register() {
    if (ObjC.available)
      registerTypes();
    else
      registerStubs();
  },
  lookup(name) {
    if (!ObjC.available)
      return null;
    const klass = ObjC.classes[name];
    if (klass === undefined)
      return null;
    return new Constructor(klass);
  },
  complete(prefix) {
    if (!ObjC.available)
      return [];
    let protocols = Object.keys(ObjC.protocols);
    let classes = Object.keys(ObjC.classes);
    if (prefix.length > 0) {
      protocols = protocols.filter(name => name.indexOf(prefix) === 0);
      classes = classes.filter(name => name.indexOf(prefix) === 0);
    }
    return protocols.concat(classes);
  }
};

function registerTypes() {
  classType = makeClassType();
  objectType = makeObjectType();
  selectorType = makeSelectorType();

  singularTypeById = {
    'c': char,
    'i': int,
    's': short,
    'l': int,
    'q': longlong,
    'C': uchar,
    'I': uint,
    'S': ushort,
    'L': ulong,
    'Q': ulonglong,
    'f': float,
    'd': double,
    'B': bool,
    'v': new Type('v'),
    '*': char.pointerTo(),
    '@': objectType,
    '@?': objectType, // TODO: blockType
    '#': classType,
    ':': selectorType,
    '?': new Type('v').pointerTo()
  };

  cachedNSString = ObjC.classes.NSString;
  cachedNSStringCtor = cachedNSString.stringWithUTF8String_;
  cachedNSNumber = ObjC.classes.NSNumber;
  cachedNSNumberCtor = cachedNSNumber.numberWithDouble_;

  global.ObjectiveC = ObjC;
  global.Instance = Instance;

  global.YES = true;
  global.NO = false;
  global.id = objectType;
  global.Class = classType;
  global.SEL = selectorType;

  global.objc_msgSend = function () {
    const args = Array.from(arguments);
    let target = args[0];
    if (target instanceof Instance)
      target = target[PRIV].impl;
    const selector = args[1];
    const argv = args.slice(2);
    const methodPrefix = (target.$kind === 'instance') ? '- ' : '+ ';
    const methodName = methodPrefix + selector;
    const method = target[methodName];
    if (method === undefined)
      throw new Error(`unrecognized selector ${selector} sent to object ${target.handle}`);

    const result = method.apply(target, argv);
    return (result instanceof ObjC.Object) ? objectType(result) : result;
  };

  cyonConverters = [
    [ObjC.classes.NSNumber.class(), objcNumberToCYON],
    [ObjC.classes.NSString.class(), objcStringToCYON],
    [ObjC.classes.NSArray.class(), objcArrayToCYON],
    [ObjC.classes.NSDictionary.class(), objcDictionaryToCYON],
  ];

  free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer']);
}

function registerStubs() {
  global.objc_msgSend = function () {
    throw new Error('Objective-C runtime not available in this process');
  };
}

function makeObjectType() {
  return makeType({
    name: 'id',
    nativeType: 'pointer',
    size: pointerSize,
    alignment: pointerSize,
    defaultValue: null,
    read: readObject,
    write: writeObject,
    cast: castObject,
    toNative: toNativeObject
  });
}

function readObject(pointer) {
  const address = Memory.readPointer(pointer);
  if (address.isNull())
    return null;
  return castObject.call(this, address);
}

function writeObject(pointer, value) {
  Memory.writePointer(pointer, toNativeObject(value));
}

function castObject(value) {
  let object;

  if (value instanceof ObjC.Object)
    object = value;
  else if (value instanceof PointerValue)
    object = new ObjC.Object(value.handle);
  else if (value instanceof NativePointer)
    object = !value.isNull() ? new ObjC.Object(value) : null;
  else if (value === null)
    object = null;
  else
    throw new Error('Invalid class value');

  return (object !== null) ? new Instance(object) : null;
}

function toNativeObject(value) {
  const type = typeof value;
  if (((type === 'object' && value !== null) || (type === 'function')) && 'handle' in value)
    return value.handle;
  else if (value instanceof NativePointer)
    return value;
  else if (value === null)
    return NULL;
  else if (type === 'string')
    return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(value));
  else if (type === 'number')
    return cachedNSNumberCtor.call(cachedNSNumber, value);
  else
    throw new Error('Invalid object value');
}

function makeClassType() {
  return makeType({
    name: 'Class',
    nativeType: 'pointer',
    size: pointerSize,
    alignment: pointerSize,
    defaultValue: null,
    read: readObject,
    write: writeObject,
    cast: castObject
  });
}

function makeSelectorType() {
  return makeType({
    name: 'SEL',
    nativeType: 'pointer',
    size: pointerSize,
    alignment: pointerSize,
    defaultValue: null,
    read: readSelector,
    write: writeSelector,
    cast: castSelector,
    toNative: toNativeSelector
  });
}

function readSelector(pointer) {
  const sel = Memory.readPointer(pointer);
  if (sel.isNull())
    return null;
  return new SelectorValue(sel);
}

function writeSelector(pointer, value) {
  Memory.writePointer(pointer, toNativeSelector(value));
}

function castSelector(value) {
  let sel;
  if (typeof value === 'string')
    sel = ObjC.selector(value);
  else if (value instanceof PointerValue)
    sel = value.handle;
  else if (value instanceof NativePointer)
    sel = !value.isNull() ? value : null;
  else if (value === null)
    sel = null;
  else
    throw new Error('Invalid selector');

  return (sel !== null) ? new SelectorValue(sel) : null;
}

function toNativeSelector(value) {
  if (value instanceof SelectorValue || value instanceof PointerValue)
    return value.handle;
  else if (value instanceof NativePointer)
    return value;
  else if (value === null)
    return NULL;
  else
    throw new Error('Invalid selector');
}

function SelectorValue(sel) {
  this[PRIV] = {
    name: ObjC.selectorAsString(sel),
    sel: sel
  };
}

Object.defineProperties(SelectorValue.prototype, {
  handle: {
    enumerable: false,
    get() {
      return this[PRIV].sel;
    }
  },
  $cyt: {
    enumerable: false,
    get() {
      return selectorType;
    }
  },
  type: {
    enumerable: false,
    writable: false,
    value(klass) {
      return parseMethodSignature(this.method(klass).types);
    }
  },
  method: {
    enumerable: false,
    writable: false,
    value(klass) {
      const {name} = this[PRIV];

      if (klass instanceof Instance)
        klass = klass[PRIV].impl;

      const prefix = (klass.$kind === 'meta-class') ? '+ ' : '- ';
      const fullName = prefix + name;
      const method = klass[fullName];
      if (method === undefined)
        throw new Error('Unknown method: ' + fullName);
      return method;
    }
  },
  toCYON: {
    enumerable: false,
    writable: false,
    value() {
      return `@selector(${this[PRIV].name})`;
    }
  }
});

function Instance(impl) {
  this[PRIV] = {
    impl: impl
  };

  const proto = {
    cy$complete: Instance.prototype.cy$complete.bind(this)
  };

  impl.retain();
  WeakRef.bind(impl, releaseObject.bind(impl.handle));

  return new Proxy(this, {
    has(target, property) {
      if (typeof property === 'symbol')
        return target[property];
      else if (property === 'prototype')
        return true;
      else if (property in impl)
        return true;

      return (property in target);
    },
    get(target, property, receiver) {
      if (typeof property === 'symbol')
        return target[property];
      else if (property === 'prototype')
        return proto;

      const value = impl[property];
      if (value !== undefined)
        return value;

      return target[property];
    },
    set(target, property, value, receiver) {
      target[property] = value;
      return true;
    },
    ownKeys(target) {
      return ['prototype'];
    },
    getOwnPropertyDescriptor(target, property) {
      return {
        writable: true,
        configurable: true,
        enumerable: true
      };
    },
    // Duktape needs these two legacy traps:
    enumerate(target) {
      return this.ownKeys();
    },
    keys(target) {
      return this.ownKeys();
    },
  });
}

Object.defineProperties(Instance.prototype, {
  handle: {
    enumerable: false,
    get() {
      return this[PRIV].impl.handle;
    }
  },
  $cyt: {
    enumerable: false,
    get() {
      return (this[PRIV].impl.$kind === 'instance') ? objectType : classType;
    }
  },
  cy$complete: {
    enumerable: false,
    writable: false,
    value(prefix) {
      const {impl} = this[PRIV];

      return collectMethodNames(this[PRIV].impl.handle).filter(name => name.indexOf(prefix) === 0);
    }
  },
  toCYON: {
    enumerable: false,
    writable: false,
    value() {
      return objcObjectToCYON(this[PRIV].impl);
    }
  }
});

Instance.box = function (value) {
  let result;

  const type = typeof value;
  if (type === 'string')
    result = cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(value)).retain();
  else
    throw new Error('Unsupported type');

  return objectType(result);
};

function releaseObject(handle) {
  new ObjC.Object(handle).release();
}

function Constructor(impl) {
  const ctor = function () {
    const instance = impl.alloc();
    WeakRef.bind(instance, releaseObject.bind(instance.handle));
    return instance;
  };

  ctor[PRIV] = {
    impl: impl
  };

  Object.setPrototypeOf(ctor, Constructor.prototype);

  return ctor;
}

extend(Constructor, Instance);

function collectMethodNames(klass) {
  const names = [];

  const numMethodsBuf = Memory.alloc(pointerSize);
  const api = ObjC.api;
  let cur = klass;
  do {
    const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
    try {
      const numMethods = Memory.readUInt(numMethodsBuf);
      for (let i = 0; i !== numMethods; i++) {
        const methodHandle = Memory.readPointer(methodHandles.add(i * pointerSize));
        const sel = api.method_getName(methodHandle);
        const nativeName = Memory.readUtf8String(api.sel_getName(sel));
        names.push(nativeName);
      }
    } finally {
      free(methodHandles);
    }

    cur = api.class_getSuperclass(cur);
  } while (!cur.isNull());

  return names;
}

function objcObjectToCYON(object, depth = 0) {
  const klass = object.$class;
  if (klass.$kind === 'meta-class') {
    if (object.$kind === 'meta-class')
      return `object_getClass(${object.$className})`;
    else
      return object.$className;
  }

  for (let i = 0; i !== cyonConverters.length; i++) {
    const [klass, convert] = cyonConverters[i];
    if (object.isKindOfClass_(klass))
      return convert(object, depth);
  }
  return `#"${object.toString()}"`;
}

function objcNumberToCYON(number, depth) {
  return number.toString();
}

function objcStringToCYON(str, depth) {
  const prefix = (depth === 0) ? '@' : '';
  return prefix + '"' + str.toString() + '"';
}

function objcArrayToCYON(array, depth) {
  const result = [];
  const count = array.count().valueOf();
  for (let i = 0; i !== count; i++) {
    const element = array.objectAtIndex_(i);
    result.push(objcObjectToCYON(element, depth + 1));
  }
  return '@[' + result.join(',') + ']';
}

function objcDictionaryToCYON(dict, depth) {
  const result = [];
  const enumerator = dict.keyEnumerator();
  let key;
  while ((key = enumerator.nextObject()) !== null) {
    const value = dict.objectForKey_(key);
    result.push(objcObjectToCYON(key, depth + 1) + ':' + objcObjectToCYON(value, depth + 1));
  }
  return '@{' + result.join(',') + '}';
}

function parseMethodSignature(sig) {
  const cursor = [sig, 0];

  const retType = readQualifiedType(cursor);
  readNumber(cursor);

  const argTypes = [];

  while (dataAvailable(cursor)) {
    const argType = readQualifiedType(cursor);
    readNumber(cursor);
    argTypes.push(argType);
  }

  return retType.functionWith(...argTypes);
}

function readQualifiedType(cursor) {
  const qualifiers = readQualifiers(cursor);
  let type = readType(cursor);
  if (qualifiers.has('const'))
    type = type.constant();
  return type;
}

const qualifierById = {
  'r': 'const',
  'n': 'in',
  'N': 'inout',
  'o': 'out',
  'O': 'bycopy',
  'R': 'byref',
  'V': 'oneway'
};

function readQualifiers(cursor) {
  const qualifiers = new Set();
  while (true) {
    const q = qualifierById[peekChar(cursor)];
    if (q === undefined)
      break;
    qualifiers.add(q);
    skipChar(cursor);
  }
  return qualifiers;
}

function readType(cursor) {
  let pointerDepth = 0;

  let id = readChar(cursor);

  while (id === '^') {
    pointerDepth++;
    id = readChar(cursor);
  }

  if (id === '@') {
    let next = peekChar(cursor);
    if (next === '?') {
      id += next;
      skipChar(cursor);
    } else if (next === '"') {
      skipChar(cursor);
      readUntil('"', cursor);
    }
  }

  let type = singularTypeById[id];
  if (type !== undefined) {
  } else if (id === '[') {
    const length = readNumber(cursor);
    const elementType = readType(cursor);
    skipChar(cursor); // ']'
    type = elementType.arrayOf(length);
  } else if (id === '{') {
    const name = readUntil('=', cursor);

    const fieldTypes = [];
    const fieldNames = [];
    while (peekChar(cursor) !== '}') {
      fieldTypes.push(readType(cursor));
      fieldNames.push(`f{fieldTypes.length}`);
    }
    skipChar(cursor); // '}'

    let structType = new Type(fieldTypes, fieldNames);
    if (name.length > 0)
      structType = structType.withName(name);
    type = structType;
  } else if (id === '(') {
    const name = readUntil('=', cursor);

    const fieldTypes = [];
    const fieldNames = [];
    while (peekChar(cursor) !== '}') {
      fieldTypes.push(readType(cursor));
      fieldNames.push(`f{fieldTypes.length}`);
    }
    skipChar(cursor); // ')'

    let unionType = new Type(fieldTypes, fieldNames, 'union'); // TODO: not implemented
    if (name.length > 0)
      unionType = unionType.withName(name);
    type = unionType;
  } else if (id === 'b') {
    readNumber(cursor);
    type = singularTypeById.i;
  } else {
    throw new Error("Unable to handle type " + id);
  }

  while (pointerDepth > 0)
    type = type.pointerTo();

  return type;
}

function readNumber(cursor) {
  let result = "";
  while (dataAvailable(cursor)) {
    const c = peekChar(cursor);
    const v = c.charCodeAt(0);
    const isDigit = v >= 0x30 && v <= 0x39;
    if (isDigit) {
      result += c;
      skipChar(cursor);
    } else {
      break;
    }
  }
  return parseInt(result);
}

function readUntil(token, cursor) {
  const buffer = cursor[0];
  const offset = cursor[1];
  const index = buffer.indexOf(token, offset);
  if (index === -1)
    throw new Error("Expected token '" + token + "' not found");
  const result = buffer.substring(offset, index);
  cursor[1] = index + 1;
  return result;
}

function readChar(cursor) {
  return cursor[0][cursor[1]++];
}

function peekChar(cursor) {
  return cursor[0][cursor[1]];
}

function skipChar(cursor) {
  cursor[1]++;
}

function dataAvailable(cursor) {
  return cursor[1] !== cursor[0].length;
}

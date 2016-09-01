# Mjølner

Cycript backend powered by Frida.

## Example

```js
const mjolner = require('@viaforensics/mjolner');

mjolner.register();

const puts = int.functionWith(char.constant().pointerTo())(dlsym(RTLD_DEFAULT, 'puts'));
/*
 * ^
 * |
 *  \ Which would be the output from the cycript compiler if you wrote:
 *    extern "C" int puts(char const*)
 */

puts('Hello');
```

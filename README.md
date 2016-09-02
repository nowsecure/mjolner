# Mjølner

Cycript compatible runtime powered by Frida.

## Example

```js
const mjolner = require('mjolner');

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

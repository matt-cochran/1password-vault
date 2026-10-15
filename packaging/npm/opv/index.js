'use strict';

// Node 26 treats `node --test <dir>` as a module path rather than a directory to scan, so
// the directory has to resolve to a file. Requiring the test files here keeps the documented
// `node --test packaging/npm/opv/` working on every Node version. The glob form
// (`node --test 'packaging/npm/opv/*.test.js'`) does not load this file. Not published:
// package.json lists only bin, install.js and uninstall.js.
require('./install.test.js');
require('./uninstall.test.js');
require('./opv.test.js');

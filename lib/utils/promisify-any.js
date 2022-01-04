const util = require("util");

module.exports = makePromisify();

function makePromisify() {
  const promisify = function (fn, options) {
    // conform options
    if (typeof options === "number") {
      options = { numArgs: options };
    } else {
      if (options === undefined) {
        options = {};
      }

      if (options.numArgs === undefined) {
        options.numArgs = 0;
      }
    }

    // deal with callback functions
    if (fn.length > options.numArgs) {
      return util.promisify(fn);
    }

    // deal with sync functions or promise-returning functions
    return function promisify(...args) {
      try {
        const r = fn.apply(this, args);
        if (r instanceof Promise) {
          return r;
        }

        return Promise.resolve(r);
      } catch (e) {
        return Promise.reject(e);
      }
    };
  };

  // method to set Promise implementation
  promisify.use = makePromisify;

  return promisify;
}

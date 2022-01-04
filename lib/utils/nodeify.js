module.exports = (promise, callback) => {
  return promise
    .then((data) => {
      if (callback) {
        callback(null, data);
      } else {
        return data;
      }

      return data;
    })
    .catch((err) => {
      if (callback) {
        callback(err);
      } else {
        throw err;
      }
    });
};

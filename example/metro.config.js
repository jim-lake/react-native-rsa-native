const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

const projectRoot = __dirname;
const test_module = path.resolve(projectRoot, '../..');

const config = {
  watchFolders: [test_module],
  resolver: {
    extraNodeModules: {
      'react-native-rsa-native': test_module,
    },
  },
};
module.exports = mergeConfig(getDefaultConfig(projectRoot), config);

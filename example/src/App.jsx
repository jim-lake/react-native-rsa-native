import React, { Component } from 'react';
import { View, Text } from 'react-native';

import generateKeys4096Demo from './generateKeys4096Demo';
import generateDemo from './generateDemo';
import signDemo from './signDemo';
import signAlgoDemo from './signAlgoDemo';
import iosDemo from './iosDemo';
import androidDemo from './androidDemo';
import keychainDemo from './keychainDemo';
import keychainECDemo from './keychainECDemo';
import keychainEdDemo from './keychainEdDemo';
import getAllKeysDemo from './getAllKeysDemo';
import updatePrivateKeyDemo from './updatePrivateKeyDemo';
import publicKeyFormatsDemo from './publicKeyFormatsDemo';
import deleteAllKeysDemo from './deleteAllKeysDemo';
import deleteIndividualKeysDemo from './deleteIndividualKeysDemo';

const runTests = async setTestStatus => {
  const tests = [
    { name: 'generateKeys4096Demo', fn: generateKeys4096Demo },
    { name: 'generateDemo', fn: generateDemo },
    { name: 'signDemo', fn: signDemo },
    { name: 'signAlgoDemo', fn: signAlgoDemo },
    { name: 'iosDemo', fn: iosDemo },
    { name: 'androidDemo', fn: androidDemo },
    { name: 'keychainDemo', fn: keychainDemo },
    { name: 'keychainECDemo', fn: keychainECDemo },
    { name: 'keychainEdDemo', fn: keychainEdDemo },
    { name: 'getAllKeysDemo', fn: getAllKeysDemo },
    { name: 'updatePrivateKeyDemo', fn: updatePrivateKeyDemo },
    { name: 'publicKeyFormatsDemo', fn: publicKeyFormatsDemo },
    { name: 'deleteAllKeysDemo', fn: deleteAllKeysDemo },
    { name: 'deleteIndividualKeysDemo', fn: deleteIndividualKeysDemo },
  ];

  setTestStatus('Running');

  for (const test of tests) {
    console.log(`START TEST: ${test.name}`);
    const result = await test.fn();
    if (!result) {
      const errorMsg = `TEST FAIL: ${test.name}`;
      console.log(errorMsg);
      setTestStatus(`Failure: ${test.name}`);
      console.log('ALL_TESTS_COMPLETED FAILED');
      return;
    }
    console.log(`TEST PASS: ${test.name}`);
  }

  console.log('ALL_TESTS_COMPLETED PASS');
  setTestStatus('Success');
};

class App extends Component {
  constructor(props) {
    super(props);
    this.state = { testStatus: 'Running' };
  }

  componentDidMount() {
    runTests(status => this.setState({ testStatus: status }));
  }

  render() {
    return (
      <View style={{ margin: 20, marginTop: 100 }}>
        <Text>Demo</Text>
        <Text testID="test-status" style={{ fontSize: 18, marginTop: 20 }}>
          Test Status: {this.state.testStatus}
        </Text>
      </View>
    );
  }
}

export default App;

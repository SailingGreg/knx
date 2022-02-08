/**
* knx.js - a KNX protocol stack in pure Javascript
* (C) 2016-2018 Elias Karakoulakis
*/

Error.stackTraceLimit = Infinity;

const knx = require('../..');
const test = require('tape');

test('KNX connect routing', function(t) {
  let ipAddr; // FILL THIS
  let ipPort; // FILL THIS

  if(!ipAddr || !ipPort) {
    t.skip('No ip/port of test device')
    t.end();
    process.exit(0);
  }
 
  var connection = knx.Connection({
    loglevel: 'debug',
    ipAddr,
    ipPort,
    handlers: {
      connected: function() {
        console.log('----------');
        console.log('Connected!');
        console.log('----------');
        t.pass('connected in routing mode');
        t.end();
        connection.disconnect();
        connection.on('disconnected', () => {
          process.exit(0);
        })
      },
      error: function() {
        t.fail('error connecting');
        t.end();
        process.exit(1);
      }
    }
  });
});

setTimeout(function() {
  console.log('Exiting with timeout...');
  process.exit(2);
}, 1000);

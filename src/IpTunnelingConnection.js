/**
 * knx.js - a KNX protocol stack in pure Javascript
 * (C) 2016-2018 Elias Karakoulakis
 */

const dgram = require('dgram');
const KnxLog = require('./KnxLog.js');
const tcpnet=require('net');

function IpTunnelingConnection(instance) {
  const log = KnxLog.get();

  instance.BindSocket = function (cb) {
    const udpSocket = dgram.createSocket('udp4');
    udpSocket.bind(() => {
      log.debug(
        'IpTunnelingConnection.BindSocket %s:%d',
        instance.localAddress,
        udpSocket.address().port
      );
      cb && cb(udpSocket);
    });
    return udpSocket;
  };

  instance.Connect = function () {
    this.localAddress = this.getLocalAddress();
    // evaluate the connection_type 
    const range=this.remoteEndpoint.range();
    if (range == "unicast") {
      // create tcp connection
      this.socket=tcpnet.createConnection({
        port:this.remoteEndpoint.port,
        host:this.remoteEndpoint.addstring 
        }, 
        ()=>{
          log.debug('connected to server!');
      });
      this.transition('connecting');
    }
    else{
      // create the socket (UDP)
      this.socket = this.BindSocket((socket) => {
        socket.on('error', (errmsg) => log.debug('Socket error: %j', errmsg));
        socket.on('message', (msg, rinfo, callback) => {
          log.debug('Inbound message: %s', msg.toString('hex'));
          this.onUdpSocketMessage(msg, rinfo, callback);
        });
        // start connection sequence
        this.transition('connecting');
      });
    }
    return this;
  };

  return instance;
}

module.exports = IpTunnelingConnection;

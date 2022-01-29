/**
* knx.js - a KNX protocol stack in pure Javascript
* (C) 2016-2018 Elias Karakoulakis
*/
import {sharedKey} from 'curve25519-js';
import { crypto } from 'crypto';
import { endianness } from 'os';

const util = require('util');

const FSM = require('./FSM');
const DPTLib = require('./dptlib');
const KnxLog = require('./KnxLog');
const KnxConstants = require('./KnxConstants');
const KnxNetProtocol = require('./KnxProtocol');
const CryptoJS = require("crypto-js");
const aesCbcMac = require("aes-cbc-mac");

// bind incoming UDP packet handler
FSM.prototype.onUdpSocketMessage = function(msg, rinfo, callback) {
  // get the incoming packet's service type ...
  try {
    const reader = KnxNetProtocol.createReader(msg);
    reader.KNXNetHeader('tmp');
    const dg = reader.next()['tmp'];
    const descr = datagramDesc(dg);
    KnxLog.get().trace('(%s): Received %s message: %j', this.compositeState(), descr, dg);
    if (!isNaN(this.channel_id) &&
      ((dg.hasOwnProperty('connstate') &&
          dg.connstate.channel_id != this.channel_id) ||
        (dg.hasOwnProperty('tunnstate') &&
          dg.tunnstate.channel_id != this.channel_id))) {
      KnxLog.get().trace('(%s): *** Ignoring %s datagram for other channel (own: %d)',
        this.compositeState(), descr, this.channel_id);
    } else {
      // ... to drive the state machine (eg "inbound_TUNNELING_REQUEST_L_Data.ind")
      const signal = util.format('inbound_%s', descr);
      if (descr === "DISCONNECT_REQUEST") {
        KnxLog.get().info("empty internal fsm queue due to %s: ", signal);
        this.clearQueue();
      }
      this.handle(signal, dg);
    }
  } catch(err) {
    KnxLog.get().debug('(%s): Incomplete/unparseable UDP packet: %s: %s',
      this.compositeState(),err, msg.toString('hex')
    );
  }
};

// bind incoming TCP packet handler

FSM.prototype.onTcpSocketMessage = function(msg, rinfo, callback){
  // get the incoming packet's service type ...
  // function's details are not yet implemented.(todo)
  // now storing the peer's public key for session_request and session_response

  try {
    const reader = KnxNetProtocol.createReader(msg);
    reader.KNXNetHeader('tmp');
    const dg = reader.next()['tmp'];
    const descr = datagramDesc(dg);
    KnxLog.get().trace('(%s): Received %s message: %j', this.compositeState(), descr, dg);

    // storing the peer's pub key
    if (descr === 'SESSION_REQUEST')  this.pubKey.client = dg.pubkey;
    if (descr === 'SESSION_RESPONSE') this.pubKey.server = dg.pubkey;

    this.handle(signal, dg);
  } catch(err) {
    KnxLog.get().debug('(%s): Incomplete/unparseable UDP packet: %s: %s',
      this.compositeState(),err, msg.toString('hex')
    );
  }

}

FSM.prototype.AddConnState = function(datagram) {
  datagram.connstate = {
    channel_id: this.channel_id,
    state: 0
  }
}

FSM.prototype.AddTunnState = function(datagram) {
  // add the remote IP router's endpoint
  datagram.tunnstate = {
    channel_id: this.channel_id,
    tunnel_endpoint: this.remoteEndpoint.addr + ':' + this.remoteEndpoint.port
  }
}

const AddCRI = (datagram) => {
  // add the CRI
  datagram.cri = {
    connection_type: KnxConstants.CONNECTION_TYPE.TUNNEL_CONNECTION,
    knx_layer: KnxConstants.KNX_LAYER.LINK_LAYER,
    unused: 0
  }
}

FSM.prototype.AddCEMI = function(datagram, msgcode) {
  const sendAck = ((msgcode || 0x11) == 0x11) && !this.options.suppress_ack_ldatareq; // only for L_Data.req
  datagram.cemi = {
    msgcode: msgcode || 0x11, // default: L_Data.req for tunneling
    ctrl: {
      frameType: 1, // 0=extended 1=standard
      reserved: 0, // always 0
      repeat: 1, // the OPPOSITE: 1=do NOT repeat
      broadcast: 1, // 0-system broadcast 1-broadcast
      priority: 3, // 0-system 1-normal 2-urgent 3-low
      acknowledge: sendAck ? 1 : 0,
      confirm: 0, // FIXME: only for L_Data.con 0-ok 1-error
      // 2nd byte
      destAddrType: 1, // FIXME: 0-physical 1-groupaddr
      hopCount: 6,
      extendedFrame: 0
    },
    src_addr: this.options.physAddr || "15.15.15",
    dest_addr: "0/0/0", //
    apdu: {
      // default operation is GroupValue_Write
      apci: 'GroupValue_Write',
      tpci: 0,
      data: 0
    }
  }
}

/*
 * submit an outbound request to the state machine
 *
 * type: service type
 * datagram_template:
 *    if a datagram is passed, use this as
 *    if a function is passed, use this to DECORATE
 *    if NULL, then just make a new empty datagram. Look at AddXXX methods
 */
FSM.prototype.Request = function(type, datagram_template, callback) {
  // populate skeleton datagram
  const datagram = this.prepareDatagram(type);
  // decorate the datagram, if a function is passed
  if (typeof datagram_template == 'function') {
    datagram_template(datagram);
  }
  // make sure that we override the datagram service type!
  datagram.service_type = type;
  const st = KnxConstants.keyText('SERVICE_TYPE', type);
  // hand off the outbound request to the state machine
  this.handle('outbound_' + st, datagram);
  if (typeof callback === 'function') callback();
}

// prepare a datagram for the given service type
FSM.prototype.prepareDatagram = function(svcType) {
  const datagram = {
      "header_length": 6,
      "protocol_version": 16, // 0x10 == version 1.0
      "service_type": svcType,
      "total_length": null, // filled in automatically
    }
    //
  AddHPAI(datagram);
  //
  switch (svcType) {
    case KnxConstants.SERVICE_TYPE.CONNECT_REQUEST:
      AddTunn(datagram);
      AddCRI(datagram); // no break!
    case KnxConstants.SERVICE_TYPE.CONNECTIONSTATE_REQUEST:
    case KnxConstants.SERVICE_TYPE.DISCONNECT_REQUEST:
      this.AddConnState(datagram);
      break;
    case KnxConstants.SERVICE_TYPE.ROUTING_INDICATION:
      this.AddCEMI(datagram, KnxConstants.MESSAGECODES['L_Data.ind']);
      break;
    case KnxConstants.SERVICE_TYPE.TUNNELING_REQUEST:
      AddTunn(datagram);
      this.AddTunnState(datagram);
      this.AddCEMI(datagram);
      break;
    case KnxConstants.SERVICE_TYPE.TUNNELING_ACK:
      this.AddTunnState(datagram);
      break;
    case KnxConstants.SERVICE_TYPE.SESSION_REQUEST: // prepare session secure request datagram
        // binary format of the the knxnet/ip session request frame
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
        // |         Header Length         |        Protocol Version       |                     |
        // |         (06h)                 |        (10h)                  |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+                     |
        // |                     Session Type Identifier                   |  KNXnet/IP secure   |
        // |                     (0951h)                                   |  Header             |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+                     |
        // |                           Total Length                        |                     |
        // |                           (26h+sizeof(HPAI))                  |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
      
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
        // |                     HPAI Control Endpoint                     |                     |
        // |                     (varaible lenght)                         |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+  Unencrypted Data   |
        // |             Diffie-Hellman Server Public Value X              |                     |
        // |             (32 Octet)                                        |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
      
      this.AddHPAI(datagram);
      // adding Diffie-Hellman Client Public Value to datagram
      const client=crypto.createDiffieHellman(2048);
      const clientPubKey=crypto.generateKeys();

      // how to add generated public key to datagram (todo)
      // datagram.clientPubKey=clientPubKey;
      this.addPubKey(datagram, clientPubKey);
      
      case KnxConstants.SERVICE_TYPE.SESSION_RESPONSE: // prepare session secure response datagram
        // binary format of the the knxnet/ip session response frame
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
        // |         Header Length         |        Protocol Version       |                     |
        // |         (06h)                 |        (10h)                  |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+                     |
        // |                     Session Type Identifier                   |  KNXnet/IP secure   |
        // |                     (0952h)                                   |  Header             |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+                     |
        // |                           Total Length                        |                     |
        // |                           (38h)                               |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
      
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
        // |                     Secure Session Identifier                 |                     |
        // |                     (2 Octet)                                 |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+  Unencrypted Data   |
        // |             Diffie-Hellman Server Public Value Y              |                     |
        // |             (32 Octet)                                        |                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+
        // |                   Message Authentication Code                  |  Encrypted Data     |
        // |                   (16 Octet)                                  |  (AES128 CCM)       |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+---------------------+

      // how to add generated public key to datagram (todo)
        const server=crypto.createDiffieHellman(2048);
        const serverPubKey=crypto.generateKeys();
      // adding Message Authentication Code (Encrypted Data)
      // datagram.serverPubKey=serverPubKey;
        this.addPubKey(datagram, serverPubKey);

      // generate session identity through ServerPublic key XOR device auth code
      // mechanism of session key are followings.
      // 1) get shared secret key using Curve25519(myprivkey, peerspubkey)
      // 2) get hash using SHA256(shared secret key)
      // 3) get sesssion key by taking first 16 bytes of hash above
      //  todo: where to place code for getting peerspubkey
      const shared_secret = server.computeSecret(this.pubKey.client);
      var hash = CryptoJS.SHA256(shared_secret);
      // convert hash to big-endian (todo)
      // assume that sha256() returns little-endian hex string
      // general mechanism of converting little endian into big endian
      var reverse_endian_hash = parseInt('0x' + hash.match(/../g).reverse().join(''));
      
      // get session key from little endian hash
      const session_key = Buffer.from(reverse_endian_hash).toString('hex', 0, 15);
      datagram.sessionId = session_key;

      // calculate Message Authentication Code (40 octets)
      // Secure Header | Secure session_identifier | (Client Public Key X ^ Server Public Key Y)
      // encrypt with device authentication code
      const resMsg = Buffer.from(datagram.header_length.toString('hex') 
                    + datagram.protocol_version.toString('hex')
                    + datagram.service_type.toString('hex')
                    + datagram.total_length.toString('hex')
                    + datagram.sessionId.toString('hex')
                    + (this.pubKey.client ^ serverPubKey));   // symbol ^ means XOR bit operation 
      const resKey = Buffer.from(this.deviceAuthenticationCode, 'hex');
      const hashLen = 16;
      datagram.mac = aesCbcMac.create(resMsg, resKey, hashLen);


      // the paper shows we should not use CBC-MAC method but CCM for calculating MAC
      // so I copied the CCM calculation example below

      // import { Buffer } from 'buffer';
      // const {
      //   createCipheriv,
      //   createDecipheriv,
      //   randomBytes
      // } = await import('crypto');
      
      // const key = 'keykeykeykeykeykeykeykey';
      // const nonce = randomBytes(12);
      
      // const aad = Buffer.from('0123456789', 'hex');
      
      // const cipher = createCipheriv('aes-192-ccm', key, nonce, {
      //   authTagLength: 16
      // });
      // const plaintext = 'Hello world';
      // cipher.setAAD(aad, {
      //   plaintextLength: Buffer.byteLength(plaintext)
      // });
      // const ciphertext = cipher.update(plaintext, 'utf8');
      // cipher.final();
      // const tag = cipher.getAuthTag();
      
      // // Now transmit { ciphertext, nonce, tag }.
      
      // const decipher = createDecipheriv('aes-192-ccm', key, nonce, {
      //   authTagLength: 16
      // });
      // decipher.setAuthTag(tag);
      // decipher.setAAD(aad, {
      //   plaintextLength: ciphertext.length
      // });
      // const receivedPlaintext = decipher.update(ciphertext, null, 'utf8');
      
      // try {
      //   decipher.final();
      // } catch (err) {
      //   throw new Error('Authentication failed!', { cause: err });
      // }
      
      // console.log(receivedPlaintext);

      // for session_response messages
      // AAD = Secure Header | Secure Session Identifier | (ECDH Client Pub Key ^ Server Pub Key)
      // Payload is empty
      // B0: first block for CBC-MAC calculation
      // Ctr0: Block counter 
      // how to implement the above content into code (todo)

      case KnxConstants.SERVICE_TYPE.SESSION_AUTHENTICATE:
        // binary format of the the knxnet/ip session authenticate frame
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+
        // |         Header Length         |        Protocol Version       |
        // |         (06h)                 |        (10h)                  |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+
        // |                     Session Type Identifier                   |
        // |                     (0953h)                                   |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+
        // |                           Total Length                        |
        // |                           (18h)                               |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+

        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+
        // |         reservered            |          User ID              |             
        // |         (00h)                 |          (1 Octet)            |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+
        // |                   Message Authentication Code                 |
        // |                   (16 Octet, CBC-MAC/CCM)                     |
        // +-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+-7-+-6-+-5-+-4-+-3-+-2-+-1-+-0-+
        // send Password

        datagram.reserved = Buffer.from(parseInt('0x00', 'hex').toString());
        // session_authentication frames must be wrapped in SECURE_WRAPPER frame for security
        // encrypt the session_authentication frames using session key.
        // available user ids are followings:
        // 00h: Reserved, shall not be used  01h: Management level access  02h-7Fh: User level access
        // 80h-FFh: Reserved, Reserved, shall not be used
        // userID must be determined by services accepted by server after authentication
        // so it is not stored here
        if (!this.authenticated)     datagram.userID = Buffer.from('00h', 'hex');

        // Message Authentication Code
        const authMsg = Buffer.from(datagram.header_length.toString('hex') 
                    + datagram.protocol_version.toString('hex')
                    + datagram.service_type.toString('hex')
                    + datagram.total_length.toString('hex')
                    + '0x00'
                    + datagram.userID.toString()
                    + (this.pubKey.client ^ serverPubKey));   // symbol ^ means XOR bit operation 
        const authKey = Buffer.from(this.deviceAuthenticationCode, 'hex');
        datagram.mac = aesCbcMac.create(authMsg, authKey, hashLen);

      default:
      KnxLog.get().debug('Do not know how to deal with svc type %d', svcType);
  }
  return datagram;
}

/*
send the datagram over the wire
*/
FSM.prototype.send = function(datagram, callback) {
  var cemitype; // TODO: set, but unused
  try {
    this.writer = KnxNetProtocol.createWriter();
    switch (datagram.service_type) {
      case KnxConstants.SERVICE_TYPE.ROUTING_INDICATION:
      case KnxConstants.SERVICE_TYPE.TUNNELING_REQUEST:
        // append the CEMI service type if this is a tunneling request...
        cemitype = KnxConstants.keyText('MESSAGECODES', datagram.cemi.msgcode);
        break;
    }
    const packet = this.writer.KNXNetHeader(datagram);
    const buf = packet.buffer;
    const svctype = KnxConstants.keyText('SERVICE_TYPE', datagram.service_type); // TODO: unused

    // where to encapsulate the KNXnet/IP frame and Message Authentication code
    // encapsulate session id using ECDH
    // for now priv_key is test key. to do: how to generate sender key and receive key 
    // if (svcType == KnxConstants.SERVICE_TYPE.SESSION_REQUEST)
    // {
      //  const SENDER_PRIV='77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
      //  const RECEIVER_PRIV='de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
      //  const senderPriv = Uint8Array.from(Buffer.from(SENDER_PRIV, 'hex'));
      //  const receiverPriv = Uint8Array.from(Buffer.from(RECEIVER_PRIV, 'hex'));
      //  const secret = sharedKey(senderPriv, receiverPriv);

      // where to generate secret key and how to append it for encrypting and decrypting 
      // the payload
    // }

    const descr = datagramDesc(datagram);
    KnxLog.get().trace('(%s): Sending %s ==> %j', this.compositeState(), descr, datagram);
    this.socket.send(
      buf, 0, buf.length,
      this.remoteEndpoint.port, this.remoteEndpoint.addr.toString(),
      (err) => {
        KnxLog.get().trace('(%s): UDP sent %s: %s %s', this.compositeState(),
          (err ? err.toString() : 'OK'), descr, buf.toString('hex')
        );
        if (typeof callback === 'function') callback(err);
      }
    );
  } catch (e) {
    KnxLog.get().warn(e);
    if (typeof callback === 'function') callback(e);
  }
}

FSM.prototype.write = function(grpaddr, value, dptid, callback) {
  if (grpaddr == null || value == null) {
    KnxLog.get().warn('You must supply both grpaddr and value!');
    return;
  }
  try {
    // outbound request onto the state machine
    const serviceType = this.useTunneling ?
      KnxConstants.SERVICE_TYPE.TUNNELING_REQUEST :
      KnxConstants.SERVICE_TYPE.ROUTING_INDICATION;
    this.Request(serviceType, function(datagram) {
      DPTLib.populateAPDU(value, datagram.cemi.apdu, dptid);
      datagram.cemi.dest_addr = grpaddr;
    }, callback);
  } catch (e) {
    KnxLog.get().warn(e);
  }
}

FSM.prototype.respond = function(grpaddr, value, dptid) {
  if (grpaddr == null || value == null) {
    KnxLog.get().warn('You must supply both grpaddr and value!');
    return;
  }
  const serviceType = this.useTunneling ?
    KnxConstants.SERVICE_TYPE.TUNNELING_REQUEST :
    KnxConstants.SERVICE_TYPE.ROUTING_INDICATION;
  this.Request(serviceType, function(datagram) {
    DPTLib.populateAPDU(value, datagram.cemi.apdu, dptid);
    // this is a READ request
    datagram.cemi.apdu.apci = "GroupValue_Response";
    datagram.cemi.dest_addr = grpaddr;
    return datagram;
  });
}

FSM.prototype.writeRaw = function(grpaddr, value, bitlength, callback) {
  if (grpaddr == null || value == null) {
    KnxLog.get().warn('You must supply both grpaddr and value!');
    return;
  }
  if (!Buffer.isBuffer(value)) {
    KnxLog.get().warn('Value must be a buffer!');
    return;
  }
  // outbound request onto the state machine
  const serviceType = this.useTunneling ?
    KnxConstants.SERVICE_TYPE.TUNNELING_REQUEST :
    KnxConstants.SERVICE_TYPE.ROUTING_INDICATION;
  this.Request(serviceType, function(datagram) {
    datagram.cemi.apdu.data = value;
    datagram.cemi.apdu.bitlength = bitlength ? bitlength : (value.byteLength * 8);
    datagram.cemi.dest_addr = grpaddr;
  }, callback);
}

// send a READ request to the bus
// you can pass a callback function which gets bound to the RESPONSE datagram event
FSM.prototype.read = function(grpaddr, callback) {
  if (typeof callback == 'function') {
    // when the response arrives:
    const responseEvent = 'GroupValue_Response_' + grpaddr;
    KnxLog.get().trace('Binding connection to ' + responseEvent);
    const binding = (src, data) => {
        // unbind the event handler
        this.off(responseEvent, binding);
        // fire the callback
        callback(src, data);
      }
      // prepare for the response
    this.on(responseEvent, binding);
    // clean up after 3 seconds just in case no one answers the read request
    setTimeout( () => this.off(responseEvent, binding), 3000);
  }
  const serviceType = this.useTunneling ?
    KnxConstants.SERVICE_TYPE.TUNNELING_REQUEST :
    KnxConstants.SERVICE_TYPE.ROUTING_INDICATION;
  this.Request(serviceType, function(datagram) {
    // this is a READ request
    datagram.cemi.apdu.apci = "GroupValue_Read";
    datagram.cemi.dest_addr = grpaddr;
    return datagram;
  });
}

FSM.prototype.Disconnect = function(cb) {
  this.transition("disconnecting");
  // machina.js removeAllListeners equivalent:
  // this.off();
}

// return a descriptor for this datagram (TUNNELING_REQUEST_L_Data.ind)
const datagramDesc = (dg) => {
  let blurb = KnxConstants.keyText('SERVICE_TYPE', dg.service_type);
  if (dg.service_type == KnxConstants.SERVICE_TYPE.TUNNELING_REQUEST ||
      dg.service_type == KnxConstants.SERVICE_TYPE.ROUTING_INDICATION) {
    blurb += '_' + KnxConstants.keyText('MESSAGECODES', dg.cemi.msgcode);
  }
  return blurb;
}

// add the control udp local endpoint. UPDATE: not needed apparnently?
const AddHPAI = (datagram) => {
  datagram.hpai = {
    protocol_type: 1, // UDP
    //tunnel_endpoint: this.localAddress + ":" + this.control.address().port
    tunnel_endpoint: '0.0.0.0:0'
  };
}

// add the tunneling udp local endpoint UPDATE: not needed apparently?
const AddTunn = (datagram) => {
  datagram.tunn = {
    protocol_type: 1, // UDP
    tunnel_endpoint: '0.0.0.0:0'
      //tunnel_endpoint: this.localAddress + ":" + this.tunnel.address().port
  };
}

// add the public key to datagram
const addPubKey=(datagram, PubKey)=>{
  datagram.pubkey=PubKey;
}

// TODO: Conncetion is obviously not a constructor, but tests call it with `new`. That should be deprecated.
function Connection(options) {
  const conn = new FSM(options);
  // register with the FSM any event handlers passed into the options object
  if (typeof options.handlers === 'object') {
    for (const [key, value] of Object.entries(options.handlers)) {
      if (typeof value === 'function') {
        conn.on(key, value);
      }
    }
  }
  // boot up the KNX connection unless told otherwise
  if (!options.manualConnect) conn.Connect();
  return conn;
};

module.exports = Connection;

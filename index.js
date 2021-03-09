const dgram = require('dgram');
const server = dgram.createSocket('udp6');
const serverTCP = require('net').createServer();
const dnsPacket = require('dns-packet');
const dns = require('dns');
const DoH = require('doh-js-client').DoH;
const { EventEmitter } = require('events');
var dnsH = new DoH('google');

dns.setServers(['8.8.8.8', '8.8.4.4']);

// https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella-
let NOERROR_RCODE = 0x00;
let SERVFAIL_RCODE = 0x02;
let NXDOMAIN_RCODE = 0x03;
let NOTIMP_RCODE = 0x04;

let CACHE_MINUTES = 0.5;

var cache = {};

var event = new EventEmitter();

server.on('error', (err) => {
	console.log(`server error:\n${err.stack}`);
	server.close();
});

serverTCP.on('error', (err) => {
	console.log(`server error:\n${err.stack}`);
	server.close();
});

serverTCP.on('connection', (socket) => {
	console.log(`TCP connection from ${socket.remoteAddress}:${socket.remotePort}`);
	socket.on('data', function(data) {
		//console.log(data.toString());
		event.emit('query', 'tcp', data, {
			address: socket.remoteAddress,
			port: socket.remotePort,
			socket
		});
	});
});

server.on('message', (msg, rinfo) => {
	console.log(`UDP connection from ${rinfo.address}:${rinfo.port}`);
	event.emit('query', 'udp', msg, rinfo);
});

function queryNotA(query, packet, type, sender) {
	var error = false;
	dns.resolve(query.name, query.type, function(err, data) {
		if (err) {
			if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
				error = true;
				console.error(err);
			}
		}

		var answerData = {
			type: 'response',
			id: packet ? packet.id : null,
			flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
			questions: [query],
			answers: []
		};

		//console.log(`qid: ${packet.id}`);

		if (error) {
			answerData.flags = SERVFAIL_RCODE;
		} else if (data) {
			if (!cache[query.name]) {
				cache[query.name] = {};
				cache[query.name][query.type] = {};
			}
			if (cache[query.name] && !cache[query.name][query.type]) {
				cache[query.name][query.type] = {};
			}
			for (var i = 0; i < data.length; i++) {
				if (query.type === 'SRV') {
					var _thisData = Object.assign({}, data[i]);
					_thisData.target = _thisData.name;
					delete _thisData.name;
					cache[query.name][query.type].data = [_thisData];
					cache[query.name][query.type].expiresAt = Date.now() + (60 * CACHE_MINUTES * 1000);
					answerData.answers.push({
						type: query.type,
						class: query.class,
						name: query.name,
						ttl: 60,
						data: _thisData
					});
				} else {
					cache[query.name][query.type].data = data;
					cache[query.name][query.type].expiresAt = Date.now() + (60 * CACHE_MINUTES * 1000);
					answerData.answers.push({
						type: query.type,
						class: query.class,
						name: query.name,
						ttl: 60,
						data: data[i]
					});
				}
			}

			//console.log(answerData.answers[0].data);
			//console.log(cache[query.name][query.type]);
		}

		if (sender) {
			if (type === 'udp') {
				server.send(dnsPacket.encode(answerData), sender.port, sender.address, function(err, bytes) {
					if (err) {
						return console.error(err);
					}

					//console.log(bytes);
					console.log(`Answered UDP request: ${query.type} ${query.name} for ${sender.address}`);
				});
			} else {
				sender.socket.write(dnsPacket.streamEncode(answerData), function() {
					console.log(`Answered TCP request: ${query.type} ${query.name} for ${sender.address}`);
					sender.socket.end();
				});
			}
		}
	});
}

function queryAorAAAA(query, packet, type, sender) {
	dns.resolve4(query.name, 'A', function(err4, data4) {
		var v4Answer = false;
		var v4Error = false;
		var v4FailError = false;
		if (err4) {
			v4Error = true;
			if (err4.code !== 'ENODATA' && err4.code !== 'ENOTFOUND') {
				console.log(`Error doing DNS lookup: ${err4}`);
				v4FailError = true;
				var answerDataError = {
					type: 'response',
					id: packet ? packet.id : null,
					flags: SERVFAIL_RCODE,
					answers: []
				};

				if (sender) {
					if (type === 'udp') {
						server.send(dnsPacket.encode(answerDataError), sender.port, sender.address, function(err, bytes) {
							if (err) {
								return console.error(err);
							}

							//console.log(bytes);
						});
					} else {
						sender.socket.write(dnsPacket.streamEncode(answerDataError), function() {
							sender.socket.end();
						});
					}
				}
				return console.error(err4);
			}
		}

		//console.log(data4);

		dns.resolve6(query.name, 'AAAA', function(err6, data6) {
			var v6Answer = false;
			var v6Error = false;
			var v6FailError = false;
			if (err6) {
				v6Error = true;
				if (err6.code !== 'ENODATA' && err6.code !== 'ENOTFOUND') {
					console.log(`Error doing DNS lookup: ${err6}`);
					v6FailError = true;
					var answerDataError = {
						type: 'response',
						id: packet ? packet.id : null,
						flags: SERVFAIL_RCODE,
						answers: []
					};

					if (sender) {
						if (type === 'udp') {
							server.send(dnsPacket.encode(answerDataError), sender.port, sender.address, function(err, bytes) {
								if (err) {
									return console.error(err);
								}

								//console.log(bytes);
							});
						} else {
							sender.socket.write(dnsPacket.streamEncode(answerDataError), function() {
								sender.socket.end();
							});
						}
					}
					return console.error(err6);
				}
			}

			//console.log(data6);

			if (!v4Error && data4.length !== 0) {
				v4Answer = true;
			}

			if (!v6Error && data6.length !== 0) {
				v6Answer = true;
			}

			//console.log(`4: ${v4Answer}`);
			//console.log(`6: ${v6Answer}`);
			//console.log(`b: ${v4Answer && v6Answer}`);

			var answerData = {
				type: 'response',
				id: packet ? packet.id : null,
				questions: [query],
				flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
				answers: []
			};

			//console.log(`qid: ${packet.id}`);

			var answerVersionData = v4Answer ? data4 : data6;
			var answerType = v4Answer ? 'A' : 'AAAA';

			var waitForDNSH = false;

			if ((answerType === 'A' && v4Error) || (answerType === 'AAAA' && v6Error)) {
				var _error = err4 || err6;
				//console.log(_error.code);
				answerData.flags = _error.code === 'ENOTFOUND' ? NXDOMAIN_RCODE : NOERROR_RCODE;
			} else if ((answerType === 'AAAA' && query.type === 'A') || (answerType === 'A' && query.type === 'AAAA')) {
				waitForDNSH = true;
				dnsH.resolve(query.name, query.type).then(function(data) {
					if (data[0] && data[0].type === 5) { // CNAME
						if (!cache[query.name]) {
							cache[query.name] = {};
							cache[query.name][query.type] = {};
						}
						if (cache[query.name] && !cache[query.name][query.type]) {
							cache[query.name][query.type] = {};
						}
						cache[query.name][query.type].data = [`CNAME:${data[0].data}`];
						cache[query.name][query.type].expiresAt = Date.now() + (60 * CACHE_MINUTES * 1000);
						answerData.answers.push({
							type: 'CNAME',
							class: query.class,
							name: query.name,
							ttl: 60,
							data: data[0].data
						});
					} else {
						if (!cache[query.name]) {
							cache[query.name] = {};
							cache[query.name][query.type] = {};
						}
						if (cache[query.name] && !cache[query.name][query.type]) {
							cache[query.name][query.type] = {};
						}
						cache[query.name][query.type].data = [];
					}

					event.emit('dnsHComplete');
				}).catch(function(err) {
					console.log(`Error doing DNS lookup: ${err}`);
					var answerDataError = {
						type: 'response',
						id: packet ? packet.id : null,
						flags: SERVFAIL_RCODE,
						answers: []
					};

					if (sender) {
						if (type === 'udp') {
							server.send(dnsPacket.encode(answerDataError), sender.port, sender.address, function(err, bytes) {
								if (err) {
									return console.error(err);
								}

								//console.log(bytes);
							});
						} else {
							sender.socket.write(dnsPacket.streamEncode(answerDataError), function() {
								sender.socket.end();
							});
						}
					}
				});
			} else {
				if (!cache[query.name]) {
					cache[query.name] = {};
					cache[query.name][query.type] = {};
				}
				if (cache[query.name] && !cache[query.name][query.type]) {
					cache[query.name][query.type] = {};
				}
				cache[query.name][query.type].data = answerVersionData;
				cache[query.name][query.type].expiresAt = Date.now() + (60 * CACHE_MINUTES * 1000);
				for (var i = 0; i < answerVersionData.length; i++) {
					answerData.answers.push({
						type: answerType,
						class: query.class,
						name: query.name,
						ttl: 60,
						data: answerVersionData[i]
					});
				}

				cache[query.name][query.type === 'A' ? 'AAAA' : 'A'] = [];

				//console.log(answerData);
			}

			//console.log(answerData);

			if (waitForDNSH) {
				// eslint-disable-next-line no-inner-declarations
				function doDoHEvent() {
					event.removeListener('dnsHComplete', doDoHEvent);
					if (sender) {
						if (type === 'udp') {
							server.send(dnsPacket.encode(answerData), sender.port, sender.address, function(err, bytes) {
								if (err) {
									return console.error(err);
								}

								//console.log(bytes);
								console.log(`Answered UDP request: ${query.type} ${query.name} for ${sender.address}`);
							});
						} else {
							sender.socket.write(dnsPacket.streamEncode(answerData), function() {
								console.log(`Answered TCP request: ${query.type} ${query.name} for ${sender.address}`);
								sender.socket.end();
							});
						}
					}
				}
				event.addListener('dnsHComplete', doDoHEvent);
			} else {
				// eslint-disable-next-line no-lonely-if
				if (sender) {
					if (type === 'udp') {
						server.send(dnsPacket.encode(answerData), sender.port, sender.address, function(err, bytes) {
							if (err) {
								return console.error(err);
							}

							//console.log(bytes);
							console.log(`Answered UDP request: ${query.type} ${query.name} for ${sender.address}`);
						});
					} else {
						sender.socket.write(dnsPacket.streamEncode(answerData), function() {
							console.log(`Answered TCP request: ${query.type} ${query.name} for ${sender.address}`);
							sender.socket.end();
						});
					}
				}
			}
		});
	});
}

event.on('query', function(type, msg, rinfo) {
	//console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
	let packet;
	if (type === 'udp') {
		packet = dnsPacket.decode(msg);
	} else {
		packet = dnsPacket.streamDecode(msg);
	}
	//console.log(packet);

	let query;

	var _throwError = SERVFAIL_RCODE;

	try {
		query = packet.questions[0];

		var supportedTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT'];

		if (!supportedTypes.includes(query.type)) {
			_throwError = NOTIMP_RCODE;
			throw new Error();
		}
	} catch (e) {
		var answerDataError = {
			type: 'response',
			id: packet ? packet.id : null,
			flags: _throwError,
			answers: []
		};

		if (type === 'udp') {
			server.send(dnsPacket.encode(answerDataError), rinfo.port, rinfo.address, function(err, bytes) {
				if (err) {
					return console.error(err);
				}

				//console.log(bytes);
				console.log(`Received invalid UDP request from ${rinfo.address}. ${_throwError === NOTIMP_RCODE ? 'Type not implemented' : 'General error'}`);
			});
		} else {
			rinfo.socket.write(dnsPacket.streamEncode(answerDataError), function() {
				console.log(`Received invalid TCP request from ${rinfo.address}. ${_throwError === NOTIMP_RCODE ? 'Type not implemented' : 'General error'}`);
				rinfo.socket.end();
			});
		}

		return;
	}

	//console.log(query.type);

	if (cache[query.name] && cache[query.name][query.type] && cache[query.name][query.type].data) {
		var answerData = {
			type: 'response',
			id: packet ? packet.id : null,
			flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
			questions: [query],
			answers: []
		};

		for (var i = 0; i < cache[query.name][query.type].data.length; i++) {
			if (typeof cache[query.name][query.type].data[i] === 'string' && cache[query.name][query.type].data[i].includes('CNAME:')) {
				answerData.answers.push({
					type: 'CNAME',
					class: query.class,
					name: query.name,
					ttl: 60,
					data: cache[query.name][query.type].data[i].split('CNAME:')[1]
				});
			} else {
				//console.log(cache[query.name][query.type].data[i]);
				answerData.answers.push({
					type: query.type,
					class: query.class,
					name: query.name,
					ttl: 60,
					data: cache[query.name][query.type].data[i]
				});
			}
		}

		if (type === 'udp') {
			server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
				if (err) {
					return console.error(err);
				}

				//console.log(bytes);
				console.log(`Answered UDP request: ${query.type} ${query.name} for ${rinfo.address} from cache`);
			});
		} else {
			rinfo.socket.end(dnsPacket.streamEncode(answerData), function() {
				console.log(`Answered TCP request: ${query.type} ${query.name} for ${rinfo.address} from cache`);
			});
		}

		if (cache[query.name] && cache[query.name][query.type] && cache[query.name][query.type].expiresAt < Date.now()) {
			console.log(`Removing ${query.type} ${query.name} from cache due to expiry and requesting new data to cache`);
			//delete cache[query.name][query.type];

			if (!['A', 'AAAA'].includes(query.type)) {
				queryNotA(query, null, null, null);
			} else {
				queryAorAAAA(query, null, null, null);
			}
		}

		//console.log(cache[query.name][query.type]);
	} else if (!['A', 'AAAA'].includes(query.type)) {
		queryNotA(query, packet, type, rinfo);
	} else {
		queryAorAAAA(query, packet, type, rinfo);
	}
});

server.on('listening', () => {
	const address = server.address();
	console.log(`UDP server listening ${address.address}:${address.port}`);
});

server.bind(41234, '::');

serverTCP.on('listening', () => {
	const address = server.address();
	console.log(`TCP server listening ${address.address}:${address.port}`);
});

serverTCP.listen(41234, '::');
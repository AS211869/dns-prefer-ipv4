const dgram = require('dgram');
const server = dgram.createSocket('udp6');
const serverTCP = require('net').createServer();
const dnsPacket = require('dns-packet');
const dns = require('dns');
const DoH = require('doh-js-client').DoH;
const { EventEmitter } = require('events');
var dnsH = new DoH('google');

// https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella-
let NOERROR_RCODE = 0x00;
let SERVFAIL_RCODE = 0x02;
let NXDOMAIN_RCODE = 0x03;
let NOTIMP_RCODE = 0x04;

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

	if (cache[query.name] && cache[query.name][query.type]) {
		var answerData = {
			type: 'response',
			id: packet.id,
			flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
			questions: [query],
			answers: []
		};

		for (var i = 0; i < cache[query.name][query.type].length; i++) {
			if (typeof cache[query.name][query.type][i] === 'string' && cache[query.name][query.type][i].includes('CNAME:')) {
				answerData.answers.push({
					type: 'CNAME',
					class: query.class,
					name: query.name,
					data: cache[query.name][query.type][i].split('CNAME:')[1]
				});
			} else {
				//console.log(cache[query.name][query.type][i]);
				answerData.answers.push({
					type: query.type,
					class: query.class,
					name: query.name,
					data: cache[query.name][query.type][i]
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
		//console.log(answerData);
	} else if (!['A', 'AAAA'].includes(query.type)) {
		//dns.setServers(['8.8.8.8']);
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
				id: packet.id,
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
				}
				for (var i = 0; i < data.length; i++) {
					if (query.type === 'SRV') {
						var _thisData = Object.assign({}, data[i]);
						_thisData.target = _thisData.name;
						delete _thisData.name;
						cache[query.name][query.type] = [_thisData];
						answerData.answers.push({
							type: query.type,
							class: query.class,
							name: query.name,
							data: _thisData
						});
					} else {
						cache[query.name][query.type] = data;
						answerData.answers.push({
							type: query.type,
							class: query.class,
							name: query.name,
							data: data[i]
						});
					}
				}

				//console.log(answerData.answers[0].data);
				//console.log(cache[query.name][query.type]);
			}

			if (type === 'udp') {
				server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
					if (err) {
						return console.error(err);
					}

					//console.log(bytes);
					console.log(`Answered UDP request: ${query.type} ${query.name} for ${rinfo.address}`);
				});
			} else {
				rinfo.socket.write(dnsPacket.streamEncode(answerData), function() {
					console.log(`Answered TCP request: ${query.type} ${query.name} for ${rinfo.address}`);
					rinfo.socket.end();
				});
			}
		});
	} else {
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

					if (type === 'udp') {
						server.send(dnsPacket.encode(answerDataError), rinfo.port, rinfo.address, function(err, bytes) {
							if (err) {
								return console.error(err);
							}

							//console.log(bytes);
						});
					} else {
						rinfo.socket.write(dnsPacket.streamEncode(answerDataError), function() {
							rinfo.socket.end();
						});
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

						if (type === 'udp') {
							server.send(dnsPacket.encode(answerDataError), rinfo.port, rinfo.address, function(err, bytes) {
								if (err) {
									return console.error(err);
								}

								//console.log(bytes);
							});
						} else {
							rinfo.socket.write(dnsPacket.streamEncode(answerDataError), function() {
								rinfo.socket.end();
							});
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
					id: packet.id,
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
							}
							cache[query.name][query.type] = [`CNAME:${data[0].data}`];
							answerData.answers.push({
								type: 'CNAME',
								class: query.class,
								name: query.name,
								data: data[0].data
							});
						} else {
							if (!cache[query.name]) {
								cache[query.name] = {};
							}
							cache[query.name][query.type] = [];
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

						if (type === 'udp') {
							server.send(dnsPacket.encode(answerDataError), rinfo.port, rinfo.address, function(err, bytes) {
								if (err) {
									return console.error(err);
								}

								//console.log(bytes);
							});
						} else {
							rinfo.socket.write(dnsPacket.streamEncode(answerDataError), function() {
								rinfo.socket.end();
							});
						}
					});
				} else {
					if (!cache[query.name]) {
						cache[query.name] = {};
					}
					cache[query.name][query.type] = answerVersionData;
					for (var i = 0; i < answerVersionData.length; i++) {
						answerData.answers.push({
							type: answerType,
							class: query.class,
							name: query.name,
							data: answerVersionData[i]
						});
					}

					cache[query.name][query.type === 'A' ? 'AAAA' : 'A'] = [];

					//console.log(answerData);
				}

				//console.log(answerData);

				if (waitForDNSH) {
					var _event = event.addListener('dnsHComplete', function() {
						if (type === 'udp') {
							server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
								_event.off();
								if (err) {
									return console.error(err);
								}

								//console.log(bytes);
								console.log(`Answered UDP request: ${query.type} ${query.name} for ${rinfo.address}`);
							});
						} else {
							rinfo.socket.write(dnsPacket.streamEncode(answerData), function() {
								console.log(`Answered TCP request: ${query.type} ${query.name} for ${rinfo.address}`);
								rinfo.socket.end();
							});
						}
					});
				} else {
					// eslint-disable-next-line no-lonely-if
					if (type === 'udp') {
						server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
							if (err) {
								return console.error(err);
							}

							//console.log(bytes);
							console.log(`Answered UDP request: ${query.type} ${query.name} for ${rinfo.address}`);
						});
					} else {
						rinfo.socket.write(dnsPacket.streamEncode(answerData), function() {
							console.log(`Answered TCP request: ${query.type} ${query.name} for ${rinfo.address}`);
							rinfo.socket.end();
						});
					}
				}
			});
		});
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
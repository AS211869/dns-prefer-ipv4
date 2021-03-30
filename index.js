const dgram = require('dgram');
const server = dgram.createSocket('udp6');
const serverTCP = require('net').createServer();
const dnsPacket = require('dns-packet');
const { EventEmitter } = require('events');
const fs = require('fs');
const path = require('path');

// https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella-
let NOERROR_RCODE = 0x00;
let SERVFAIL_RCODE = 0x02;
let NXDOMAIN_RCODE = 0x03;
let NOTIMP_RCODE = 0x04;

let CACHE_MINUTES = 5;

var cache = {};

if (fs.existsSync(path.join(__dirname, 'cache.json'))) {
	console.log('Cache file exists, loading data from cache file');
	cache = JSON.parse(fs.readFileSync(path.join(__dirname, 'cache.json')));
}

function saveCache() {
	console.log('Saving to cache file');
	fs.writeFileSync(path.join(__dirname, 'cache.json'), JSON.stringify(cache));
}

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

function dnsQuery(name, type, packet, cb) {
	const socket = dgram.createSocket('udp4');

	const buf = dnsPacket.encode({
		type: 'query',
		id: packet ? packet.id : null,
		flags: dnsPacket.RECURSION_DESIRED,
		questions: [{
			type,
			name
		}]
	});

	socket.on('message', message => {
		//console.log(dnsPacket.decode(message));
		socket.close();
		cb(null, dnsPacket.decode(message));
	});

	socket.on('error', error => {
		socket.close();
		cb(error, null);
	});

	socket.send(buf, 0, buf.length, 53, '8.8.8.8');
}

function queryNotA(query, packet, type, sender) {
	var thisCache = {};
	if (cache[query.name]) {
		thisCache = cache[query.name];
	}
	thisCache[query.type] = {};

	var error = false;
	dnsQuery(query.name, query.type, packet, function(err, data) {
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
			answerData = data;
			answerData.id = packet ? packet.id : null;

			thisCache[query.type].data = answerData;
			if (answerData.answers[0]) {
				thisCache[query.type].expiresAt = Date.now() + (answerData.answers[0].ttl * 1000);
			} else {
				thisCache[query.type].expiresAt = Date.now() + (CACHE_MINUTES * 60 * 1000);
			}
			cache[query.name] = thisCache;
			saveCache();
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
	dnsQuery(query.name, 'A', packet, function(err4, data4) {
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
					questions: [query],
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

		dnsQuery(query.name, 'AAAA', packet, function(err6, data6) {
			var thisCache = {};
			if (cache[query.name]) {
				thisCache = cache[query.name];
			}
			thisCache[query.type] = {};

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
						questions: [query],
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

			if (!v4Error && data4.answers.length !== 0) {
				if (data4.answers.length === 1 && data4.answers[0].type === 'CNAME') {
					v4Answer = false;
				} else {
					v4Answer = true;
				}
			}

			if (!v6Error && data6.answers.length !== 0) {
				if (data6.answers.length === 1 && data6.answers[0].type === 'CNAME') {
					v6Answer = false;
				} else {
					v6Answer = true;
				}
			}

			//console.log(`4: ${v4Answer}`);
			//console.log(`6: ${v6Answer}`);
			//console.log(`b: ${v4Answer && v6Answer}`);

			var data4Data = data4;
			data4Data.id = packet ? packet.id : null;
			var data6Data = data6;
			data6Data.id = packet ? packet.id : null;

			var answerVersionData = v4Answer ? data4.answer : data6.answer;
			var answerType = v4Answer ? 'A' : 'AAAA';

			if (!v4Answer && !v6Answer) {
				var answerData = query.type === 'A' ? data4Data : data6Data;
				if (answerData.authorities.length > 0) {
					thisCache[query.type].data = answerData;
					thisCache[query.type].expiresAt = Date.now() + (answerData.authorities[0].data.minimum * 1000);
					cache[query.name] = thisCache;
					saveCache();
				}
				if (sender) {
					if (type === 'udp') {
						server.send(dnsPacket.encode(answerData), sender.port, sender.address, function(err, bytes) {
							if (err) {
								return console.error(err);
							}

							//console.log(bytes);
						});
					} else {
						sender.socket.write(dnsPacket.streamEncode(answerData), function() {
							sender.socket.end();
						});
					}
				}
			} else if ((answerType === 'AAAA' && query.type === 'A') || (answerType === 'A' && query.type === 'AAAA')) {
				// eslint-disable-next-line no-redeclare
				var answerData = answerType === 'A' ? data4Data : data6Data;
				answerData.questions[0].type = query.type;

				var _ttl = answerData.answers[0] ? answerData.answers[0].ttl : 0;

				if (answerData.answers[0].type !== 'CNAME') {
					answerData.answers = [];
				} else {
					answerData.answers = answerData.answers.slice(0, 1);
				}

				//console.log(answerData);

				thisCache[query.type].data = answerData;
				thisCache[query.type].expiresAt = Date.now() + (_ttl * 1000);
				cache[query.name] = thisCache;
				saveCache();

				if (sender) {
					if (type === 'udp') {
						server.send(dnsPacket.encode(answerData), sender.port, sender.address, function(err, bytes) {
							if (err) {
								return console.error(err);
							}

							//console.log(bytes);
						});
					} else {
						sender.socket.write(dnsPacket.streamEncode(answerData), function() {
							sender.socket.end();
						});
					}
				}
			} else {
				// eslint-disable-next-line no-redeclare
				var answerData = query.type === 'A' ? data4Data : data6Data;
				thisCache[query.type].data = answerData;
				if (answerData.answers[0]) {
					thisCache[query.type].expiresAt = Date.now() + (answerData.answers[0].ttl * 1000);
				} else {
					thisCache[query.type].expiresAt = Date.now() + (CACHE_MINUTES * 60 * 1000);
				}
				var cachedOtherRecord = query.type === 'A' ? data6Data : data4Data;
				if (answerData.answers[0].type !== 'CNAME') {
					cachedOtherRecord.answers = [];
				} else {
					cachedOtherRecord.answers = answerData.answers.slice(0, 1);
				}
				thisCache[query.type === 'A' ? 'AAAA' : 'A'] = {};
				thisCache[query.type === 'A' ? 'AAAA' : 'A'].data = cachedOtherRecord;
				if (answerData.answers[0]) {
					thisCache[query.type === 'A' ? 'AAAA' : 'A'].expiresAt = Date.now() + (answerData.answers[0].ttl * 1000);
				} else {
					thisCache[query.type === 'A' ? 'AAAA' : 'A'].expiresAt = Date.now() + (CACHE_MINUTES * 60 * 1000);
				}
				cache[query.name] = thisCache;
				saveCache();
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

		//var supportedTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT'];
		var supportedTypes = ['A', 'AAAA', 'CAA', 'CNAME', 'DNAME', 'DNSKEY', 'DS', 'HINFO', 'MX', 'NS', 'NSEC', 'NSEC3', 'NULL', 'PTR', 'SOA', 'SRV', 'TXT'];

		if (!supportedTypes.includes(query.type)) {
			_throwError = NOTIMP_RCODE;
			throw new Error();
		}
	} catch (e) {
		var answerDataError = {
			type: 'response',
			id: packet ? packet.id : null,
			flags: _throwError,
			questions: [query],
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
		var _answerData = Object.assign({}, cache[query.name][query.type].data);
		_answerData.id = packet ? packet.id : null;

		var dataAnswers = _answerData.answers;
		var expiresAt = cache[query.name][query.type].expiresAt;

		for (var i = 0; i < dataAnswers.length; i++) {
			var ttlLeft = Math.floor((expiresAt - Date.now()) / 1000);
			if (ttlLeft < 0) {
				ttlLeft = 0;
			}
			dataAnswers[i].ttl = ttlLeft;
		}

		if (type === 'udp') {
			server.send(dnsPacket.encode(_answerData), rinfo.port, rinfo.address, function(err, bytes) {
				if (err) {
					return console.error(err);
				}

				//console.log(bytes);
				console.log(`Answered UDP request: ${query.type} ${query.name} for ${rinfo.address} from cache`);
			});
		} else {
			rinfo.socket.end(dnsPacket.streamEncode(_answerData), function() {
				console.log(`Answered TCP request: ${query.type} ${query.name} for ${rinfo.address} from cache`);
			});
		}

		if (cache[query.name] && cache[query.name][query.type] && cache[query.name][query.type].expiresAt < Date.now()) {
			console.log(`Cache for ${query.type} ${query.name} expired. Requesting new data to cache`);
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
const dgram = require('dgram');
const server = dgram.createSocket('udp4');
const dnsPacket = require('dns-packet');
const dns = require('dns');
const DoH = require('doh-js-client').DoH;
const { EventEmitter } = require('events');
var dnsH = new DoH('google');

// https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella-
let NOERROR_RCODE = 0x00;
let SERVFAIL_RCODE = 0x02;
let NXDOMAIN_RCODE = 0x03;

var cache = {};

var event = new EventEmitter();

server.on('error', (err) => {
	console.log(`server error:\n${err.stack}`);
	server.close();
});

server.on('message', (msg, rinfo) => {
	//console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
	var packet = dnsPacket.decode(msg);
	//console.log(packet);

	let query = packet.questions[0];

	//console.log(query.type);

	if (cache[query.name] && cache[query.name][query.type]) {
		var answerData = {
			type: 'response',
			id: packet.id,
			answers: []
		};

		for (var i = 0; i < cache[query.name][query.type].length; i++) {
			if (cache[query.name][query.type][i].includes('CNAME:')) {
				answerData.answers.push({
					type: 'CNAME',
					class: query.class,
					name: query.name,
					data: cache[query.name][query.type][i].split('CNAME:')[1]
				});
			} else {
				answerData.answers.push({
					type: query.type,
					class: query.class,
					name: query.name,
					data: cache[query.name][query.type][i]
				});
			}
		}

		server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
			if (err) {
				return console.error(err);
			}

			//console.log(bytes);
			console.log(`Answered request: ${query.type} ${query.name} for ${rinfo.address} from cache`);
		});
	} else if (!['A', 'AAAA'].includes(query.type)) {
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
				answers: []
			};

			//console.log(`qid: ${packet.id}`);

			if (error) {
				answerData.flags = SERVFAIL_RCODE;
			} else if (data) {
				cache[query.name] = {};
				cache[query.name][query.type] = data;
				for (var i = 0; i < data.length; i++) {
					answerData.answers.push({
						type: query.type,
						class: query.class,
						name: query.name,
						data: data[i]
					});
				}

				//console.log(answerData);
			}

			server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
				if (err) {
					return console.error(err);
				}

				//console.log(bytes);
				console.log(`Answered request: ${query.type} ${query.name} for ${rinfo.address}`);
			});
		});
	} else {
		dns.resolve4(query.name, 'A', function(err4, data4) {
			var v4Answer = false;
			var v4Error = false;
			var v4FailError = false;
			if (err4) {
				v4Error = true;
				if (err4.code !== 'ENODATA' && err4.code !== 'ENOTFOUND') {
					v4FailError = true;
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
						v6FailError = true;
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
						if (data[0].type === 5) { // CNAME
							cache[query.name] = {};
							cache[query.name][query.type] = [`CNAME:${data[0].data}`];
							answerData.answers.push({
								type: 'CNAME',
								class: query.class,
								name: query.name,
								data: data[0].data
							});
						}

						event.emit('dnsHComplete');
					}).catch(function(err) {
						console.error(err);
					});
				} else {
					for (var i = 0; i < answerVersionData.length; i++) {
						cache[query.name] = {};
						cache[query.name][query.type] = answerVersionData;
						answerData.answers.push({
							type: answerType,
							class: query.class,
							name: query.name,
							data: answerVersionData[i]
						});
					}

					//console.log(answerData);
				}

				console.log(answerData);
				if (waitForDNSH) {
					event.addListener('dnsHComplete', function() {
						server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
							if (err) {
								return console.error(err);
							}

							//console.log(bytes);
							console.log(`Answered request: ${query.type} ${query.name} for ${rinfo.address}`);
						});
					});
				} else {
					server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
						if (err) {
							return console.error(err);
						}

						//console.log(bytes);
						console.log(`Answered request: ${query.type} ${query.name} for ${rinfo.address}`);
					});
				}
			});
		});
	}
});

server.on('listening', () => {
	const address = server.address();
	console.log(`server listening ${address.address}:${address.port}`);
});

server.bind(41234);
const dgram = require('dgram');
const server = dgram.createSocket('udp4');
const dnsPacket = require('dns-packet');
const dns = require('dns');

// https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella-
let NOERRROR_RCODE = 0x00;
let SERVFAIL_RCODE = 0x02;
let NXDOMAIN_RCODE = 0x03;

server.on('error', (err) => {
	console.log(`server error:\n${err.stack}`);
	server.close();
});

server.on('message', (msg, rinfo) => {
	console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
	var packet = dnsPacket.decode(msg);
	console.log(packet);

	let query = packet.questions[0];

	console.log(query.type);

	if (!['A', 'AAAA'].includes(query.type)) {
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

			console.log(`qid: ${packet.id}`);

			if (error) {
				answerData.flags = SERVFAIL_RCODE;
			} else if (data) {
				for (var i = 0; i < data.length; i++) {
					answerData.answers.push({
						type: query.type,
						class: query.class,
						name: query.name,
						data: data[i]
					});
				}

				console.log(answerData);
			}

			server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
				if (err) {
					return console.error(err);
				}

				console.log(bytes);
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

			console.log(data4);

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

				console.log(data6);

				if (!v4Error && data4.length !== 0) {
					v4Answer = true;
				}

				if (!v6Error && data6.length !== 0) {
					v6Answer = true;
				}

				console.log(`4: ${v4Answer}`);
				console.log(`6: ${v6Answer}`);
				console.log(`b: ${v4Answer && v6Answer}`);

				var answerData = {
					type: 'response',
					id: packet.id,
					answers: []
				};

				console.log(`qid: ${packet.id}`);

				var answerVersionData = v4Answer ? data4 : data6;
				var answerType = v4Answer ? 'A' : 'AAAA';

				if ((answerType === 'A' && v4Error) || (answerType === 'AAAA' && v6Error)) {
					var _error = err4 || err6;
					console.log(_error.code);
					answerData.flags = _error.code === 'ENOTFOUND' ? NXDOMAIN_RCODE : NOERROR_RCODE;
				} else if ((answerType === 'AAAA' && query.type === 'A') || (answerType === 'A' && query.type === 'AAAA')) {
					// do not add answers
				} else {
					for (var i = 0; i < answerVersionData.length; i++) {
						answerData.answers.push({
							type: answerType,
							class: query.class,
							name: query.name,
							data: answerVersionData[i]
						});
					}

					console.log(answerData);
				}

				server.send(dnsPacket.encode(answerData), rinfo.port, rinfo.address, function(err, bytes) {
					if (err) {
						return console.error(err);
					}

					console.log(bytes);
				});
			});
		});
	}
});

server.on('listening', () => {
	const address = server.address();
	console.log(`server listening ${address.address}:${address.port}`);
});

server.bind(41234);
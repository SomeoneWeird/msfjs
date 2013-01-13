
var msfjs = require('../lib')();

var msf = msfjs.Metasploit;

msf.on("loaded", function() {

	console.log('loaded');

	msf.listSessions(function(sessions) {
		console.log(sessions);
	});

});
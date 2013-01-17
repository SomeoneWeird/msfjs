var Metasploit 	= require('./metasploit.js'),
		Exploits	 	= require('./exploits.js'),
		Meterpreter = require('./meterpreter.js'),
		Payloads		= require('./payloads.js');


module.exports = function(options) {

	if(!options) options = {
		path: "/opt/pentest/msf3"
	};

	var msf = new Metasploit(options);

	return {
		Metasploit: 	msf,
		Exploits: 		new Exploits(msf, options),
		Payloads:  		new Payloads(msf, options),
		Meterpreter:  Meterpreter(msf)		
	}

}

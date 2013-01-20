var Session = require('./session.js');

var msf = null;

var Meterpreter = function(exploit, options) {

	this.exploit = exploit;

	this.payload = "windows/meterpreter/reverse_tcp";

	if(options.payload && ~options.payload.indexOf("meterpreter")) {
		// Check for custom meterpreter (not reverse_tcp)
		this.payload = options.payload;
	}

	this.options = options || {};

	this.events = null;

}

Meterpreter.prototype.handle = function(process, events) {

	this.events = events;

	var PROMPT = "meterpreter >";

	var checkForSession = function(data) {

		data = data.toString().trim().replace(/\s{2,}/g,'').replace(/\u001b\[\d{1,}m/g, '');

		if(!data) return;

		var session = data.match(/session\s\d{1,}\sopened\s\((.*):(\d{1,5})\s->\s(.*):(\d{1,5})\)/);

		if(session) {

			this.session = new Session({
				process: 		process,
				events: 		events,
				connection: {
					from: 		{
						host: session[1],
						port: session[2]
					},
					to: 			{
						host: session[3],
						port: session[4]
					}
				},
				access: {
					exploit: this.exploit,
					payload: this.payload,
					options: this.options
				}
			});

			process.stdout.removeAllListeners('data');

			msf.sessions.push(this.session);

			events.emit("success", this.session);

			events.on("kill", function() {

				msf.sessions.splice(msf.sessions.indexOf(this.session), 1);
				this.session.process.stdin.write('exit\n');
				this.session.emit("killed");

			}.bind(this));

			process.stdout.on('data', checkForPrompt.bind(this));
			process.stdout.on('data', checkForClose.bind(this));

		}

	}

	var checkForPrompt = function(data) {

		data = data.toString().trim().replace(/\s{2,}/g,'').replace(/\u001b\[\d{1,}m/g, '');

		if(!data) return;

		if(data == PROMPT) {
			this.session.emit('prompt');
		}

	}

	var checkForClose = function(data) {

		data = data.toString().trim().replace(/\s{2,}/g,'').replace(/\u001b\[\d{1,}m/g, '');

		var session = data.match(/Meterpreter\ssession\s\d{1,}\sclosed./);

		if(session) {

			this.session.emit("close");

			process.stdout.removeAllListeners('data');
			process.stderr.removeAllListeners('data');

			this.session = null;

		}

	}

	var checkForError = function(data) {

		data = data.toString().trim().replace(/\s{2,}/g,'').replace(/\u001b\[\d{1,}m/g, '');

		if(~data.indexOf('[-]')) {

			var error = data;

			var s = data.match(/([A-Z_]{1,}_[A-Z_]{1,}).*Command=(\d{1,})/);

			if(s) {

				error = {
					CODE: s[1],
					ERRNO: s[2],
					MESSAGE: s.input
				};

			}

			events.emit("error", error);

			return;

		}

	}

	process.stdout.on('data', checkForSession.bind(this));
	process.stdout.on('data', checkForError.bind(this));

}

Meterpreter.prototype.addOption = function(key, value) {
	this.options[key] = value;
}

Meterpreter.prototype.removeOption = function(key) {
	delete this.options[key];
}

module.exports = function(framework) {
	msf = framework;
	return Meterpreter;
}
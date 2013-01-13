var events 				= require('events'),
		util					= require('util'),
		child_process = require('child_process');

var Metasploit = function(options) {

	this.path = options.path;

	this.sessions = [];

}

util.inherits(Metasploit, events.EventEmitter);

Metasploit.prototype.update = function() {

	console.log("Updating MSF installation at " + this.path);

	var update = child_process.spawn("svn", [ "up", this.path ]);

	update.stdout.on('data', function(data) {

		data = data.toString();

		if(~data.indexOf('At revision')) {
			this.emit('updated', data.split(' ').splice(-1));
			return;
		}

		if(~data.indexOf('Updating') || ~data.indexOf('[*]')) return;

		var tmp = data.split(/\s{2,}/);

		this.emit("update", {
			type: tmp[0],
			file: tmp[1].replace('\n', '')
		});

	}.bind(this));

	update.stderr.on('data', function(err) {
		console.log(err.toString());
	});

	update.on('exit', function() {
		this.emit('updated');
	});

}

Metasploit.prototype.listSessions = function(cb) {
	cb(this.sessions);
}

module.exports = Metasploit;
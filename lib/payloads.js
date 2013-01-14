var child_process = require('child_process');

var Payloads = function(options) {

	this.path = options.path;

	this.payloads = [];

	this.gatherPayloads();

}

Payloads.prototype.gatherPayloads = function() {

	child_process.exec(this.path + '/msfpayload -l', function(err, stdout, stderr) {

		var payloads = [];

		stdout.split('\n').forEach(function(line) {

			if(~line.indexOf('/') && !~line.indexOf("[37m|")) {

				line = line.replace(/\s{2,}/g, ' ').trim().split(' ');

				var payload = {
					payload: line[0],
					success: line[1],
					description: line.splice(2).join(' ')
				}

				payloads.push(payload);

			}

		});

		this.payloads = payloads;

		console.log("Loaded payloads.");

	}.bind(this));

}

Payloads.prototype.getPayloads = function(cb) {

	cb(this.payloads);
	
};

Payloads.prototype.create = function(options, cb) {

	var filetypes = {
		c: 					'c',
		perl: 			'p',
		ruby: 			'y',
		raw: 				'r',
		js: 				'j',
		javascript: 'j',
		exe: 				'x',
		dll: 				'd',
		vba: 				'v',
		war: 				'w'
	}

	if(!filetypes[options.type]) {
		console.error(options.type + " is not a valid msfpayload type, defaulting to exe.");
		options.type = 'x';
	} else {
		options.type = filetypes[options.type];
	}

	var opts = [];

	for(var option in options.options) {
		opts.push([ option, options.options[option] ].join('='));
	}

	opts = opts.join(' ');

	var filename = options.filename;

	child_process.exec(this.path + '/msfpayload ' + [ options.payload, opts, options.type ].join(" ") + " > " + filename, function(err, stdout, stderr) {
		cb({
			filename: filename
		});
	});

}

module.exports = Payloads;

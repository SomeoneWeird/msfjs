
var msfjs = require('../lib')();

var msf = msfjs.Metasploit;

msf.on('update', function(data) {
	switch(data.type) {
		case 'A': {
			console.log("Added file " + data.file);
			break;
		}
		case 'U':
		case 'G': {
			console.log("Updated file " + data.file);
			break;
		}
		case 'D': {
			console.log("Deleted file " + data.file);
			break;
		}
	}
});

msf.on('updated', function(revision) {
	console.log("Finished updating, now at revision " + revision);
});

msf.update();
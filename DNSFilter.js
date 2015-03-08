var fs = require('fs'),
	os = require('os');

function DNSFilter(callback) {

	var self = this;
	this._blacklist = [];
	this._whitelist = [];

	fs.readFile('blacklist.txt', { encoding: 'utf-8' }, function(err, data){

		if (err) throw err;

		self._blacklist = data.split(os.EOL);

		fs.readFile('whitelist.txt', { encoding: 'utf-8' }, function(err, data){

			if (err) throw err;

			self._whitelist = data.split(os.EOL);

			callback();
		});

	});
}

DNSFilter.prototype.checkPass = function(domain) {
	
	for (var i = 0; i < this._blacklist[i]; i++) {
		if (new Regex(this._blacklist[i]).test(domain)) return false;
	}

	return true;
}

// receives and returns array of hostnames
DNSFilter.prototype.filter = function(batch) {
	return _.filter(batch, this.checkPass);
}

module.exports = DNSFilter;

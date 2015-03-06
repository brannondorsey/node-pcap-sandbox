var util = require('util'),
	EventEmitter = require('events').EventEmitter,
    pcap = require("pcap"),
    _ = require('underscore'),
    moment = require('moment'),
    DNSFilter = require('./DNSFilter');

var eventEmitter = new EventEmitter();

function DNSMap(options, callback){
	
	var self = this;

	var options = options || {};

	var maxListeners = options.maxListeners || 10;
	eventEmitter.setMaxListeners(10);

	// defaults
	this._interface = options.interface || 'en1';
	this._captureFilter = options.captureFilter || 'port 53';
	this._debug = options.debug || false;
	this._debounce = options.debounce || null; // in milliseconds
	this._debounceLock = false;
	this._chunkTime = options.chunkTime || 30 * 1000;
	this._useDNSFilter = options.dnsFilter || true;

	this._addresses = []; // interface addresses
	this.devices = {}; // network client dictionary keyed by mac addresses
	this.chunkDevices = {}; // report all new dns since last chunk

	if (this._debug) console.log('pcap version: ' + pcap.lib_version);

	var pcapSession = pcap.createSession(this._interface, this._captureFilter);

	pcapSession.findalldevs().forEach(function (dev) {
	    
	    if (pcapSession.device_name === dev.name) {
	        dev.addresses.forEach(function (address) {
	            self._addresses.push(address);
	        });
	    }
	});

	pcapSession.on('packet', function(raw_packet) {

		try {

	        var packet = pcap.decode.packet(raw_packet);

	        eventEmitter.emit('packet', packet);

	        if (self._debounce != null) {

	        	if (self._debounceLock) return;
	        	else {

	        		eventEmitter.emit('debouncedPacket', packet);
	        		self._debounceLock = true;

	        		// block packets until debounce milliseconds pass
	        		setTimeout(function(){
	        			self._debounceLock = false;
	        		}, self._debounce);
	        	}
	        }

	        if (packet.link.ip.protocol_name == 'UDP' &&
	        	packet.link.ip.udp.dns != undefined) {
	            
	        	if (self._debug) {
	        		console.log("DNS packet received from " 
	        			+ packet.link.ip.saddr + " (" + packet.link.shost 
	        			+ ") to " + packet.link.ip.daddr + " (" 
	        			+ packet.link.dhost + ")");
	        	}

	            if (!self.devices[packet.link.shost]) {
	            	self.devices[packet.link.shost] = {};
	            	self.devices[packet.link.shost].ips = [];
	            	self.devices[packet.link.shost].questions = [];
	            }

	            if (!self.chunkDevices[packet.link.shost]) {
	            	self.chunkDevices[packet.link.shost] = {};
	            	self.chunkDevices[packet.link.shost].ips = [];
	            	self.chunkDevices[packet.link.shost].questions = [];
	            }

	            var device = self.devices[packet.link.shost];
	            var chunkDevice = self.chunkDevices[packet.link.shost];

	            // add sender ip to list of ips for known device if not already present
	            if (device.ips.indexOf(packet.link.ip.saddr) == -1) {
	            	device.ips.push(packet.link.ip.saddr);
	            }

	            // same with chunk devices
	            if (chunkDevice.ips.indexOf(packet.link.ip.saddr) == -1) {
	            	chunkDevice.ips.push(packet.link.ip.saddr);
	            }

	            var question = packet.link.ip.udp.dns.question;
	            var answer = packet.link.ip.udp.dns.answer;
	            
	            if (question.length > 0 && answer.length == 0) {
	                
	                var q = {};
	                q.timestamp = (new Date(packet.pcap_header.time_ms).toISOString());
	            	q.unix = Math.floor(packet.pcap_header.time_ms);
	                q.question = question;
	                device.questions.push(q);
	                chunkDevice.questions.push(q);
	            }
	        }

	    } catch (err) {
	        if (self._debug) console.error(err);
	    }

	});

	setInterval(function(){
		eventEmitter.emit('chunk', self.chunkDevices);
		self.chunkDevices = {};
	}, self._chunkTime);

	this._dnsFilter = new DNSFilter(callback);
};

// returns array of objects: { domain: "", timestamp: 1}
// options: { mac: "", chunkData: {}} 
// chunkData is optional. When included chunkData will be queried 
// rather than self.devices 
DNSMap.prototype.getDNSQuestionList = function(options) {
	
	var self = this;

	var data = [];

	var devices = options.chunkData || self.devices;
	// console.log(util.inspect(devices, { depth: null, color: true }));

	if (options.mac) {
		data = data.concat(getListOfQuestions(devices[mac]));
	} else {
		for (var hw in devices) {
			data = data.concat(getListOfQuestions(devices[hw]));
		}
	}

	return data;

	function getListOfQuestions(device) {
		
		var data = [];

		if (device != undefined) {
			
			for (var i = 0; i < device.questions.length; i++) {
				var question = device.questions[i].question;
				for (var j = 0; j < question.length; j++) {
					data.push({
						domain: question[j].qname,
						timestamp: question[j].timestamp
					});
				}
			}
		}

		return data;
	};
}

DNSMap.prototype.on = function(evt, func) {

	if (evt == 'packet' ||
		evt == 'chunk' ||
		evt == 'debouncedPacket') {
		eventEmitter.on(evt, func);
		return true;
	}

	return false;
}

module.exports = DNSMap;
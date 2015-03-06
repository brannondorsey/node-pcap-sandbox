#!/usr/bin/env node

/*global process require exports */

var DNSMap = require('./DNSMap'),
moment = require('moment'),
util = require('util');

dnsMap = new DNSMap({
    interface: 'en1',
    debug: false,
    chunkTime: 5 * 1000,
    debounce: 500
});

dnsMap.on('chunk', function(chunk){
	for (var device in chunk) {
		console.log(device);
		var questions = dnsMap.getDNSQuestionList(device, chunk);
		for (var i = 0; i < questions.length; i++) {
			console.log("    " + questions[i].domain + "    " + moment(questions[i].timestamp).format("YYYY-MM-DD hh:mm:ss.SS A"));
		}
	}
});
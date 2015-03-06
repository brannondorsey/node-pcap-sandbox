#!/usr/bin/env node

/*global process require exports */

var util = require('util'),
    pcap = require("pcap");

var pcap_session = pcap.createSession('en1', 'port 53');

// libpcap's internal version numnber
console.log('pcap version: ' + pcap.lib_version);

// Listen for packets, decode them, and feed the simple printer.  No tricks.
pcap_session.on('packet', function (raw_packet) {


    try {

        var packet = pcap.decode.packet(raw_packet);

        if (packet.link.ip.protocol_name == 'UDP') {
            
            console.log("Timestamp:  " + (new Date(1425529415259.071).toISOString()));
            console.log("Sender MAC: " + packet.link.shost);
            console.log("Sender IP:  " + packet.link.ip.saddr);
            console.log("Sender Port:" + packet.link.ip.udp.sport);

            // console.log(util.inspect(packet, { depth: null, color: true }));

            if (packet.link.ip.udp.dns != undefined) {
                console.log("Packet Type: DNS");
            }

            var question = packet.link.ip.udp.dns.question;
            
            if (question.length > 0) {
                
                console.log("Question: ");
                
                for (var i = 0; i < question.length; i++) {
                    console.log("   qname: " + question[i].qname + " | qtype: " + question[i].qtype);
                }
            }
    
            console.log()
        }

    } catch (err) {
        console.error(err);
    }
    
});

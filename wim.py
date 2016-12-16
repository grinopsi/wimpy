#!/usr/bin/env python

import sqlite3 as sql
import re
import argparse
import pyshark
import signal

dbName = ""
conn = None
args = None
iface = None
capture = None

def ParseArgs():
	global dbName
	global args
	global iface
	parser = argparse.ArgumentParser(description='Monitor')
	parser.add_argument('-d', '--database', dest='database', type=str, required=False, default='wim.py.db',
                    help='Name of sqlite database')
        parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, 
	 	help='Interface to use for sniffing and packet injection')

	args = parser.parse_args()
	dbName = args.database
	iface = args.interface
	print args.database


def InitDB():
	global conn
	global dbName	

	conn = sql.connect(dbName)
	
	conn.execute("CREATE TABLE IF NOT EXISTS ProbeSummary (Mac TEXT, SSID TEXT, Events INT, FirstSeen TEXT, LastSeen TEXT, PRIMARY KEY (Mac, SSID))")
	conn.execute("CREATE TABLE IF NOT EXISTS ProbeDetail (Mac TEXT, SSID TEXT, LastSeen TEXT, PRIMARY KEY (Mac, SSID, LastSeen))")
	
	conn.commit()



def InsertProbe(mac, ssid):
	global conn
	global dbName

	conn.execute("INSERT INTO ProbeDetail (Mac, SSID, LastSeen) VALUES (?,?,strftime('%Y-%m-%d %H:%M:%f', 'now'))", (mac, ssid))

	conn.execute("""INSERT OR REPLACE INTO ProbeSummary (Mac, SSID, Events, FirstSeen, LastSeen)
		VALUES (?, ?, 
		COALESCE((SELECT Events+1 FROM ProbeSummary WHERE Mac=? AND SSID=?),0),
		COALESCE((SELECT FirstSeen FROM ProbeSummary WHERE Mac=? AND SSID=?), strftime('%Y-%m-%d %H:%M:%f', 'now')),
		strftime('%Y-%m-%d %H:%M:%f', 'now')
		)
		""", (mac, ssid, mac, ssid, mac, ssid))

	
	conn.commit()

def Listen(interface):
        global capture
	# capture = pyshark.LiveCapture(interface='en1',display_filter='wlan.fc.type_subtype eq 4 or wlan.fc.type_subtype eq 5')
	
	try:
		capture = pyshark.LiveCapture(interface=interface, bpf_filter='subtype probereq')
		#capture.set_debug()
                # user sniff_continuously(packet_count=5) to limit number of sniffed packets
                capture.apply_on_packets(parsePacket)
		#for packet in capture.sniff_continuously(): 
		#	parsePacket(packet)
	except pyshark.capture.capture.TSharkCrashException, e:
		print "Error %s:" % e.args[0]

def parsePacket(pkt):
        try:
            #print "%s --> %s" % (pkt.wlan.get_field("sa"),pkt.wlan_mgt.get_field("ssid"))
            match = re.search('(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', pkt.wlan.get_field("sa"))
            print "[%s] --> <%s>" % (match.group(0), pkt.wlan_mgt.get_field("ssid").rstrip())
        except AttributeError, ae:
            print pkt.wlan
            for name in pkt.wlan.field_names:
                print "[%s] --> %s" % (name, pkt.wlan.get_field(name))
def stop(signal, frame):
    global capture
    # stop channel hopping
    print "stopping"

def main():
	global iface
	ParseArgs()
        signal.signal(signal.SIGINT, stop)
	#InitDB()
	try :
		#InsertProbe('00:00:00:00:00:00', 'TEST0000')

		Listen(iface)
	except sql.Error, e:
		print "Error %s:" % e.args[0]
		sys.exit(1)
	finally:
		if conn:
			conn.close()


if __name__ == "__main__":
    main()

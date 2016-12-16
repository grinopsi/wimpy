#!/usr/bin/env python

import sqlite3 as sql
import argparse
import pyshark

dbName = ""
conn = None
args = None
iface = None

def ParseArgs():
	global dbName
	global args
	global iface
	parser = argparse.ArgumentParser(description='Monitor')
	parser.add_argument('-d', '--database', dest='database', type=str, required=False, default='wim.py.db'
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
	# capture = pyshark.LiveCapture(interface='en1',display_filter='wlan.fc.type_subtype eq 4 or wlan.fc.type_subtype eq 5')
	# capture = pyshark.LiveCapture(interface='en1', bpf_filter='subtype probereq')
	
	try:
		#capture = pyshark.LiveCapture(interface=interface, bpf_filter='subtype probereq')
		capture = pyshark.LiveCapture(interface=interface)
		capture.set_debug()

		for packet in capture.sniff_continuously():
			parsePacket(packet)
			#print "New packet:", packet.eth.destination
	except pyshark.capture.capture.TSharkCrashException, e:
		print "Error %s:" % e.args[0]

def parsePacket(pkt):
	for line in pkt:
		print "LINE:", line

def main():
	global iface
	ParseArgs()
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

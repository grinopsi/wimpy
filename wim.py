#!/usr/bin/env python

import sqlite3 as sql
import argparse

dbName = ""
conn = None

def ParseArgs():
	global dbName
	parser = argparse.ArgumentParser(description='Monitor')
	parser.add_argument('--database',
                    help='Name of sqlite database')

	args = parser.parse_args()
	dbName = args.database
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

def main():
	ParseArgs()
	InitDB()
	InsertProbe('00:00:00:00:00:00', 'TEST0000')


if __name__ == "__main__":
    main()



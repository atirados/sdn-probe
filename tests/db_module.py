#!/usr/bin/python

import MySQLdb as mdb

con = mdb.connect(host='10.0.0.1', port=3306, user='root', passwd='mysqlpass', db='sonda')
with con:
	cur = con.cursor()
	cur.execute("SELECT * FROM HOSTS")
	rows = cur.fetchall()
	for row in rows:
		print row
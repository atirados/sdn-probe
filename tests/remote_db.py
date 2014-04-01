#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb

con = mdb.connect(host="10.0.0.1", port=3306, user='root', passwd='mysqlpass', db='test');

with con: 

    cur = con.cursor()
    cur.execute("SELECT * FROM prueba")

    rows = cur.fetchall()

    for row in rows:
        print row
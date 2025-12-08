import sqlite3 as sql
import bcrypt


def newUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
    con.commit()
    con.close()


def getUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()


# def getUsers():
#     con = sql.connect("databaseFiles/database.db")
#     cur = con.cursor()
#     cur.execute("SELECT * FROM id7-tusers")
#     con.close()
#     return cur

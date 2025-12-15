import sqlite3 as sql
import bcrypt
from flask import g, current_app
from datetime import datetime
import math


def newUser(name, email, password):
    con = get_db()
    cur = con.cursor()
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    try:
        cur.execute(
            "INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
            (email, hashed, name),
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


def getUser(email, password):
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT id, name, email, password FROM users WHERE email = ?", (email,))
    result = cur.fetchone()
    con.close()
    if result is None:
        return None
    # Check password with bcrypt
    if bcrypt.checkpw(password.encode("utf-8"), result[3]):
        return {"id": result[0], "name": result[1], "email": result[2]}
    return None


def get_db():
    if "db" not in g:
        db_path = current_app.config.get("DATABASE")
        g.db = sql.connect(db_path)
        g.db.row_factory = sql.Row
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def getLogs():
    con = get_db()
    cur = con.execute("SELECT * FROM logs ORDER BY created DESC")
    rows = cur.fetchall()
    return [dict(r) for r in rows]


def createLog(project, author, starttime, endtime, message):
    con = get_db()
    cur = con.cursor()
    try:
        worktime = hrs
        cur.execute(
            "INSERT INTO logs (author, message, worktime, starttime, endtime, project) VALUES (?, ?, ?, ?)",
            (author, message, worktime, starttime, endtime, project),
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


# def getUsers():
#     con = sql.connect("databaseFiles/database.db")
#     cur = con.cursor()
#     cur.execute("SELECT * FROM id7-tusers")
#     con.close()
#     return cur

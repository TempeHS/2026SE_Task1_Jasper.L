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
        if isinstance(starttime, str):
            start = datetime.fromisoformat(starttime)
        else:
            start = starttime
        if isinstance(endtime, str):
            end = datetime.fromisoformat(endtime)
        else:
            end = endtime
        time_diff = (end - start).total_seconds() / 3600
        if time_diff < 0:
            return False
        worktime = round(time_diff * 4) / 4
        cur.execute(
            "INSERT INTO logs (author, message, worktime, starttime, endtime, project) VALUES (?, ?, ?, ?, ?, ?)",
            (author, message, worktime, starttime, endtime, project),
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


def editLog(id, project, starttime, endtime, message):
    con = get_db()
    cur = con.cursor()
    try:
        if isinstance(starttime, str):
            start = datetime.fromisoformat(starttime)
        else:
            start = starttime
        if isinstance(endtime, str):
            end = datetime.fromisoformat(endtime)
        else:
            end = endtime
        time_diff = (end - start).total_seconds() / 3600
        if time_diff < 0:
            con.close()
            return False
        worktime = round(time_diff * 4) / 4
        cur.execute(
            "UPDATE logs SET project = ?, message = ?, worktime = ?, starttime = ?, endtime = ? WHERE id = ?",
            (project, message, worktime, starttime, endtime, id),
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


def getLog(log_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
    row = cur.fetchone()
    if row:
        return dict(row)
    return None


# def getUsers():
#     con = sql.connect("databaseFiles/database.db")
#     cur = con.cursor()
#     cur.execute("SELECT * FROM id7-tusers")
#     con.close()
#     return cur

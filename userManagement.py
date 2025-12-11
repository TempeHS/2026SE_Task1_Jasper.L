import sqlite3 as sql
import bcrypt


def newUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    try:
        cur.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed)
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


def getUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE email = ?", (email,))
    result = cur.fetchone()
    con.close()
    if result is None:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), result[0])


# def getUsers():
#     con = sql.connect("databaseFiles/database.db")
#     cur = con.cursor()
#     cur.execute("SELECT * FROM id7-tusers")
#     con.close()
#     return cur

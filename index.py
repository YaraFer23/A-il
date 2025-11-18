import json
import random
import hashlib
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file
import re
import binascii

# Límites y patrones
MAX_UNAME_LEN = 50
MAX_EMAIL_LEN = 254
MAX_PASSWORD_LEN = 128
MIN_PASSWORD_LEN = 6
MAX_NAME_LEN = 100
MAX_TOKEN_LEN = 256
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "bmp"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def loadDatabaseSettings(pathjs):
    pathjs = Path(pathjs)
    if pathjs.exists():
        with pathjs.open() as data:
            return json.load(data)
    return False


# ------------------------------------------------------
#  PARCHE 5: Tokens más seguros con hashing SHA-256
# ------------------------------------------------------
def generate_token():
    base = f"{datetime.now().timestamp()}{random.random()}{random.random()}"
    return hashlib.sha256(base.encode()).hexdigest()


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


# ------------------------------------------------------
# Validaciones de Parche 4
# ------------------------------------------------------
def is_valid_username(u):
    if not isinstance(u, str):
        return False
    u = u.strip()
    if not u or len(u) > MAX_UNAME_LEN:
        return False
    return bool(re.match(r'^[A-Za-z0-9_.-]+$', u))


def is_valid_email(e):
    if not isinstance(e, str):
        return False
    e = e.strip()
    if not e or len(e) > MAX_EMAIL_LEN:
        return False
    return bool(EMAIL_RE.match(e))


def is_valid_password(p):
    if not isinstance(p, str):
        return False
    if len(p) < MIN_PASSWORD_LEN or len(p) > MAX_PASSWORD_LEN:
        return False
    return True


def sanitize_name(name):
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or len(name) > MAX_NAME_LEN:
        return None
    safe = re.sub(r'[^A-Za-z0-9_\-\.]', '_', name)
    if '..' in safe or '/' in safe or '\\' in safe:
        return None
    return safe


def valid_token(tok):
    if not isinstance(tok, str):
        return False
    tok = tok.strip()
    if not tok or len(tok) > MAX_TOKEN_LEN:
        return False
    if not re.match(r'^[A-Za-z0-9_\-\.]+$', tok):
        return False
    return True


def decode_base64_limited(b64_str, max_bytes=MAX_IMAGE_BYTES):
    if not isinstance(b64_str, str):
        return None
    try:
        decoded = base64.b64decode(b64_str, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) > max_bytes:
        return None
    return decoded


def to_int_strict(v):
    try:
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    except Exception:
        pass
    return None


# ------------------------------------------------------
#  PARCHE 5: Validación de autorización
# ------------------------------------------------------
def require_auth(token):
    """Verifica si el token enviado existe y pertenece a un usuario."""
    if not valid_token(token):
        return None

    token_hash = hash_token(token)

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT id_Usuario FROM AccesoToken WHERE token_hash=%s',
                (token_hash,)
            )
            R = cursor.fetchall()
            if not R:
                return None
            return R[0][0]
    except:
        return None
    finally:
        db.close()


# ------------------------------------------------------
#  REGISTRO
# ------------------------------------------------------
@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}

    if not ('uname' in request.json and 'email' in request.json and 'password' in request.json):
        return {"R": -1}

    uname = request.json.get("uname")
    email = request.json.get("email")
    password = request.json.get("password")

    if not is_valid_username(uname):
        return {"R": -1}
    if not is_valid_email(email):
        return {"R": -1}
    if not is_valid_password(password):
        return {"R": -1}

    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Usuario VALUES (NULL, %s, %s, MD5(%s))',
                (uname.strip(), email.strip(), password)
            )
            new_id = cursor.lastrowid
            db.commit()
            return {"R": 0, "D": new_id}
    except:
        return {"R": -2}
    finally:
        db.close()


# ------------------------------------------------------
#  LOGIN (Parche 5: guarda token hasheado)
# ------------------------------------------------------
@post('/Login')
def Login():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}

    if not ('uname' in request.json and 'password' in request.json):
        return {"R": -1}

    uname = request.json.get("uname")
    password = request.json.get("password")

    if not is_valid_username(uname) or not is_valid_password(password):
        return {"R": -1}

    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT id FROM Usuario WHERE uname=%s AND password=MD5(%s)',
                (uname.strip(), password)
            )
            R = cursor.fetchall()
    except:
        db.close()
        return {"R": -2}

    if not R:
        db.close()
        return {"R": -3}

    user_id = R[0][0]

    # Generar token seguro
    raw_token = generate_token()
    hashed = hash_token(raw_token)

    try:
        with db.cursor() as cursor:
            cursor.execute('DELETE FROM AccesoToken WHERE id_Usuario=%s', (user_id,))
            cursor.execute('INSERT INTO AccesoToken VALUES (%s, %s, NOW())', (user_id, hashed))
            db.commit()
            return {"R": 0, "D": raw_token}
    except:
        return {"R": -4}
    finally:
        db.close()


# ------------------------------------------------------
#  SUBIR IMAGEN (parche 5: requiere token válido)
# ------------------------------------------------------
@post('/Imagen')
def Imagen():
    tmp = Path('tmp')
    img = Path('img')
    tmp.mkdir(exist_ok=True)
    img.mkdir(exist_ok=True)

    if not request.json:
        return {"R": -1}

    if not all(k in request.json for k in ("name", "data", "ext", "token")):
        return {"R": -1}

    token = request.json.get("token")
    user_id = require_auth(token)
    if not user_id:
        return {"R": -2}

    name_raw = request.json.get("name")
    ext_raw = request.json.get("ext")
    data_b64 = request.json.get("data")

    if not isinstance(name_raw, str) or not isinstance(ext_raw, str) or not isinstance(data_b64, str):
        return {"R": -1}

    name = sanitize_name(name_raw)
    if not name:
        return {"R": -1}

    ext = ext_raw.strip().lower()
    if "\x00" in ext or ext not in ALLOWED_IMAGE_EXT:
        return {"R": -1}

    decoded = decode_base64_limited(data_b64)
    if decoded is None:
        return {"R": -1}

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    with open(f"tmp/{user_id}", "wb") as f:
        f.write(decoded)

    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Imagen VALUES (NULL, %s, %s, %s)',
                (name, "img/", user_id)
            )
            cursor.execute(
                'SELECT MAX(id) FROM Imagen WHERE id_Usuario=%s',
                (user_id,)
            )
            idImagen = cursor.fetchall()[0][0]

            cursor.execute(
                'UPDATE Imagen SET ruta=%s WHERE id=%s',
                (f"img/{idImagen}.{ext}", idImagen)
            )
            db.commit()

            shutil.move(f"tmp/{user_id}", f"img/{idImagen}.{ext}")
            return {"R": 0, "D": idImagen}
    except:
        return {"R": -3}
    finally:
        db.close()


# ------------------------------------------------------
# DESCARGAR (parche 5: control estricto de acceso)
# ------------------------------------------------------
@post('/Descargar')
def Descargar():
    if not request.json:
        return {"R": -1}

    if not ("token" in request.json and "id" in request.json):
        return {"R": -1}

    token = request.json.get("token")
    user_id = require_auth(token)
    if not user_id:
        return {"R": -2}

    idImagen = to_int_strict(request.json.get("id"))
    if idImagen is None or idImagen < 0:
        return {"R": -1}

    dbcnf = loadDatabaseSettings("db.json")
    db = mysql.connector.connect(
        host="localhost", port=dbcnf["port"],
        database=dbcnf["dbname"],
        user=dbcnf["user"],
        password=dbcnf["password"]
    )

    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT name, ruta FROM Imagen WHERE id=%s AND id_Usuario=%s",
                (idImagen, user_id)
            )
            R = cursor.fetchall()
    except:
        db.close()
        return {"R": -3}

    if not R:
        db.close()
        return {"R": -4}

    filename = Path(R[0][1]).name
    return static_file(filename, str(Path("img").resolve()))


# ------------------------------------------------------
if __name__ == "__main__":
    run(host="localhost", port=8080, debug=True)

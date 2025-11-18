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
    sjson = False
    if pathjs.exists():
        with pathjs.open() as data:
            sjson = json.load(data)
    return sjson
    
"""
function loadDatabaseSettings(pathjs):
    string = file_get_contents(pathjs);
    json_a = json_decode(string, true);
    return json_a;

"""
def getToken():
    tiempo = datetime.now().timestamp()
    numero = random.random()
    cadena = str(tiempo) + str(numero)
    numero2 = random.random()
    cadena2 = str(numero)+str(tiempo)+str(numero2)
    m = hashlib.sha1()
    m.update(cadena.encode())
    P = m.hexdigest()
    m = hashlib.md5()
    m.update(cadena.encode())
    Q = m.hexdigest()
    return f"{P[:20]}{Q[20:]}"


def is_valid_username(u):
    if not isinstance(u, str):
        return False
    u = u.strip()
    if not u or len(u) > MAX_UNAME_LEN:
        return False
    # permitir letras, números, guión bajo y puntos
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
    # reemplazar caracteres peligrosos por '_'
    safe = re.sub(r'[^A-Za-z0-9_\-\.]', '_', name)
    # prevenir secuencias de traversal
    if '..' in safe or '/' in safe or '\\' in safe:
        return None
    return safe


def valid_token(tok):
    if not isinstance(tok, str):
        return False
    tok = tok.strip()
    if not tok or len(tok) > MAX_TOKEN_LEN:
        return False
    # token básico: solo caracteres imprimibles
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
        # aceptar ints o strings que representen ints
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    except Exception:
        pass
    return None


"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *        "uname": "XXX",
 *        "email": "XXX",
 *        "password": "XXX"
 * 
 * */
"""
@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )
    ####/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
    # TODO checar si estan vacio los elementos del json
    if not R:
        return {"R":-1}
    # Validaciones adicionales (Parche 4)
    uname = request.json.get("uname")
    email = request.json.get("email")
    password = request.json.get("password")
    if not is_valid_username(uname):
        return {"R":-1}
    if not is_valid_email(email):
        return {"R":-1}
    if not is_valid_password(password):
        return {"R":-1}
    # TODO validar correo en json
    # TODO Control de error de la DB
    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Usuario VALUES (NULL, %s, %s, MD5(%s))',
                (uname.strip(), email.strip(), password)
            )
            R = cursor.lastrowid
            db.commit()
        db.close()
    except Exception as e:
        print(e) 
        return {"R":-2}
    return {"R":0,"D":R}

"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *        "uname": "XXX",
 *        "password": "XXX"
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():
    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )
    ###/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    ######/
    R = 'uname' in request.json  and 'password' in request.json
    # TODO checar si estan vacio los elementos del json
    if not R:
        return {"R":-1}
    # Validaciones adicionales (Parche 4)
    uname = request.json.get("uname")
    password = request.json.get("password")
    if not is_valid_username(uname):
        return {"R":-1}
    if not is_valid_password(password):
        return {"R":-1}
    # TODO validar correo en json
    # TODO Control de error de la DB
    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT id FROM Usuario WHERE uname=%s AND password=MD5(%s)',
                (uname.strip(), password)
            )
            R = cursor.fetchall()
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-2}
    
    if not R:
        db.close()
        return {"R":-3}
    
    T = getToken();
    with open("/tmp/log","a") as log:
        log.write(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"\n')
        log.write(f'insert into AccesoToken values({R[0][0]},"{T}",now())\n')
    
    try:
        with db.cursor() as cursor:
            cursor.execute('DELETE FROM AccesoToken WHERE id_Usuario=%s', (R[0][0],))
            cursor.execute('INSERT INTO AccesoToken VALUES (%s, %s, NOW())', (R[0][0], T))
            db.commit()
            db.close()
            return {"R":0,"D":T}
    except Exception as e:
        print(e)
        db.close()
        return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 *         "token: "XXX"
 *        "name": "XXX",
 *         "data": "XXX",
 *         "ext": "PNG"
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()
    
    ###/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    ######/
    R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
    if not R:
        return {"R":-1}

    name_raw = request.json.get("name")
    ext_raw = request.json.get("ext")
    data_b64 = request.json.get("data")
    token = request.json.get("token")

    # Validaciones generales (Parche 4)
    if not isinstance(name_raw, str) or not isinstance(ext_raw, str) or not isinstance(data_b64, str):
        return {"R":-1}

    if not valid_token(token):
        return {"R":-1}

    name = sanitize_name(name_raw)
    if not name:
        return {"R":-1}

    ext = ext_raw.strip().lower()
    if "\x00" in ext:
        return {"R":-1}

    if ext not in ALLOWED_IMAGE_EXT:
        return {"R":-1}

    decoded = decode_base64_limited(data_b64, MAX_IMAGE_BYTES)
    if decoded is None:
        return {"R":-1}

    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )

    TKN = token;
    
    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT id_Usuario FROM AccesoToken WHERE token=%s',
                (TKN,)
            )
            R = cursor.fetchall()
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-2}
    
    if not R:
        db.close()
        return {"R":-2}

    id_Usuario = R[0][0];

    with open(f'tmp/{id_Usuario}',"wb") as imagen:
        imagen.write(decoded)
    
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Imagen VALUES (NULL, %s, %s, %s)',
                (name, "img/", id_Usuario)
            )
            cursor.execute(
                'SELECT MAX(id) AS idImagen FROM Imagen WHERE id_Usuario=%s',
                (id_Usuario,)
            )
            R = cursor.fetchall()
            idImagen = R[0][0];

            cursor.execute(
                'UPDATE Imagen SET ruta=%s WHERE id=%s',
                (f'img/{idImagen}.{ext}', idImagen)
            )
            db.commit()

            shutil.move('tmp/'+str(id_Usuario), 'img/'+str(idImagen)+'.'+ext)
            return {"R":0,"D":idImagen}
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-3}


"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 *         "token: "XXX",
 *         "id": "XXX"
 * 
 * Debe retornar un Token 
 * */
"""
@post('/Descargar')
def Descargar():
    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )
    
    ###/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    ######/
    R = 'token' in request.json and 'id' in request.json  
    if not R:
        return {"R":-1}
    
    token = request.json.get("token")
    idImagen_raw = request.json.get("id")

    if not valid_token(token):
        return {"R":-1}

    idImagen = to_int_strict(idImagen_raw)
    if idImagen is None:
        return {"R":-1}
    if idImagen < 0:
        return {"R":-1}

    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT id_Usuario FROM AccesoToken WHERE token=%s',
                (token,)
            )
            R = cursor.fetchall()
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-2}
        
    
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT name, ruta FROM Imagen WHERE id=%s AND id_Usuario=%s',
                (idImagen, R[0][0])
            )
            R = cursor.fetchall()
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-3}
    if not R:
        db.close()
        return {"R":-4}
    filename = Path(R[0][1]).name
    return static_file(filename, str(Path("img").resolve()))

if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True)
import json
import random
import hashlib
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



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
    # TODO validar correo en json
    # TODO Control de error de la DB
    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Usuario VALUES (NULL, %s, %s, MD5(%s))',
                (request.json["uname"], request.json["email"], request.json["password"])
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
    
    # TODO validar correo en json
    # TODO Control de error de la DB
    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT id FROM Usuario WHERE uname=%s AND password=MD5(%s)',
                (request.json["uname"], request.json["password"])
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
 * 
 *         "token: "XXX"
 *        "name": "XXX",
 *         "data": "XXX",
 *         "ext": "PNG"
 * 
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
    
    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )

    TKN = request.json['token'];
    
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
    
    
    id_Usuario = R[0][0];
    with open(f'tmp/{id_Usuario}',"wb") as imagen:
        imagen.write(base64.b64decode(request.json['data'].encode()))
    
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Imagen VALUES (NULL, %s, %s, %s)',
                (request.json["name"], "img/", id_Usuario)
            )
            cursor.execute(
                'SELECT MAX(id) AS idImagen FROM Imagen WHERE id_Usuario=%s',
                (id_Usuario,)
            )
            R = cursor.fetchall()
            idImagen = R[0][0];

            cursor.execute(
                'UPDATE Imagen SET ruta=%s WHERE id=%s',
                (f'img/{idImagen}.{request.json["ext"]}', idImagen)
            )
            db.commit()

            shutil.move('tmp/'+str(id_Usuario), 'img/'+str(idImagen)+'.'+str(request.json['ext']))
            return {"R":0,"D":idImagen}
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-3}
    

"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *         "token: "XXX",
 *         "id": "XXX"
 * 
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
    
    TKN = request.json['token'];
    idImagen = request.json['id'];
    
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
        
    
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT name, ruta FROM Imagen WHERE id=%s',
                (idImagen,)
            )
            R = cursor.fetchall()
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-3}
    print(Path("img").resolve(),R[0][1])
    return static_file(R[0][1],Path(".").resolve())

if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True)

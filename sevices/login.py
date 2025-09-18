# login service con las rutas de logueo y registro de usuarios
import requests
from flask import Flask, request, jsonify
from datetime import datetime
import sqlite3
import jwt

app = Flask(__name__)

DB_NAME = "usuarios.db" 
SECRET_KEY = "mi_clave_secreta"


def init_db():
    with sqlite3.connect(DB_NAME) as conn: #investigar
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                contrasena TEXT NOT NULL
            )
        """)
        conn.commit()

def registrar_usuario(data):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO usuarios (username, contrasena)
            VALUES (?, ?)
        """, (
            data["username"],
            data["contrasena"],
        ))
        conn.commit()
        return cursor.lastrowid# devuelve el ID de la última fila insertada para verificar que todo ok

#payload: datos que se envían en el cuerpo de una petición HTTP 
def validar_payload(data):
    campos = ["username", "contrasena"]
    for campo in campos:
        if campo not in data:
            return False, f"Falta el campo: {campo}"
    return True, "OK"

def validar_token(auth):
    if auth != tokentrue:
        return jsonify(({"message": "ERROR: Unauthorized"}), 401)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("contrasena")

    init_db()
    cursor = conn.cursor()
    row = cursor.execute("""
        SELECT username, contrasena from usuarios WHERE username = ? 
    """), (username)
    cursor.fetchone()
    cursor.close()

    if username adn password == row[1]:
        token = jwt.encode(
            {
                "user": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # expira en 30 min
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"token": token})
    return jsonify({"error": "Credenciales inválidas"}), 401

@app.route("/registro", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("contrasena")

    try:
        init_db()
        registrar_usuario()
        cursor.close()
    except Exception as e:
        print(f"Error al registrar usuario {e}")
                       
    return jsonify({"success": "Usuario registrado con exito"}), 200

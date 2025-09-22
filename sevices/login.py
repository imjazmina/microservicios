# login service con las rutas de logueo y registro de usuarios
import requests
from flask import Flask, request, jsonify
from datetime import datetime
import sqlite3
import jwt
import os
from dotenv import load_dotenv

app = Flask(__name__)

DB_NAME = "usuarios.db" 
SECRET_KEY = os.getenv("SECRET_KEY")


def init_db():
    with sqlite3.connect(DB_NAME) as conn: # investigar with
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
            return False, "Formato incompleto"
    return True, "OK"


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    valido, msg = validar_payload(data, ["username", "contrasena"])
    if not valido:
        return jsonify({"error": msg}), 400

    username = data.get("username")
    password = data.get("contrasena")

    init_db()
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        row = cursor.execute("""
            SELECT username, contrasena from usuarios WHERE username = ? 
        """), (username)
        cursor.fetchone()
        cursor.close()

    if username and password == row[0]:
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
def registro():
    data = request.get_json()

    valido, msg = validar_payload(data, ["username", "contrasena"])
    if not valido:
        return jsonify({"error": msg}), 400

    username = data.get("username")
    password = data.get("contrasena")

    try:
        init_db()
        user_id = registrar_usuario(data)
        return jsonify({"message": "Usuario registrado con éxito", "id": user_id}), 201
    except Exception as e:
        return jsonify({"error": f"Error al registrar usuario: {e}"}), 500
                       

@app.route("/verify-token", methods=["GET"])
def verify_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Token requerido"}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True, "user": payload["user"]}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
    print( "Server running in localhost")
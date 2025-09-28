# 🐧 Proyecto de Microservicios - Autenticación y Productos

Este proyecto implementa una arquitectura de **microservicios** con Python y Flask.  
Incluye un servicio de **autenticación de usuarios** (login, registro, verificación de tokens JWT) y un servicio de **gestión de productos** (listado protegido por autenticación).

---

## 📌 Estructura del Proyecto

```bash
microservicios/
├── auth_service/        # Servicio de autenticación (registro, login, verify-token)
│   └── app.py
├── product_service/     # Servicio de productos (listado protegido)
│   └── app.py
└── README.md

````
---

## 🚀 Servicios

### 1. **Auth Service** (`localhost:5000`)
- **Registro de usuarios**
  - `POST /registro`
  - Request:
    ```json
    {
      "username": "jazmin",
      "contrasena": "12345"
    }
    ```
  - Response:
    ```json
    {
      "message": "Usuario registrado con éxito",
      "id": 1
    }
    ```

- **Login de usuarios**
  - `POST /login`
  - Request:
    ```json
    {
      "username": "jazmin",
      "contrasena": "12345"
    }
    ```
  - Response:
    ```json
    {
      "token": "<jwt_token>"
    }
    ```

- **Verificación de token**
  - `GET /verify-token`
  - Header:
    ```
    Authorization: Bearer <jwt_token>
    ```
  - Response:
    ```json
    {
      "valid": true,
      "user": "jazmin"
    }
    ```

---

### 2. **Product Service** (`localhost:5001`)
- **Listado de productos**
  - `GET /productos`
  - Header:
    ```
    Authorization: Bearer <jwt_token>
    ```
  - Response:
    ```json
    [
      { "id_producto": 1, "nombre": "leche", "precio": 35.0 },
      { "id_producto": 2, "nombre": "yogurt", "precio": 12.0 },
      { "id_producto": 3, "nombre": "queso", "precio": 25.0 }
    ]
    ```

---

## ⚙️ Requisitos

- Python 3.10+
- Flask
- PyJWT
- Requests
- SQLite (incluido en Python)

Instalación de dependencias:
```bash
pip install flask pyjwt requests
````

---

## ▶️ Ejecución

1. Clonar el repositorio o copiar los archivos.

2. Iniciar el servicio de autenticación:

   ```bash
   cd auth_service
   python app.py
   ```

   Disponible en [http://127.0.0.1:5000](http://127.0.0.1:5000)

3. Iniciar el servicio de productos:

   ```bash
   cd product_service
   python app.py
   ```

   Disponible en [http://127.0.0.1:5001](http://127.0.0.1:5001)

---

## 🧪 Pruebas con Postman

1. **Registrar usuario** con `POST /registro`.
2. **Hacer login** con `POST /login` y copiar el token JWT.
3. **Acceder a productos** con `GET /productos` enviando el header:

   ```
   Authorization: Bearer <token>
   ```

---

## 📚 Aprendizaje

Este proyecto es una introducción práctica a:

* Arquitectura de **microservicios**.
* Uso de **Flask** para exponer APIs REST.
* Manejo de **JWT** para autenticación.
* Comunicación entre servicios vía HTTP.
* Uso de **SQLite** como base de datos ligera.

---

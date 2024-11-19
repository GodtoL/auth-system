# Gestión de Usuarios con Seguridad (Práctica)

Este es un proyecto de práctica que implementa un sistema de gestión de usuarios con seguridad mejorada, incluyendo protección CSRF, autenticación con JWT y gestión de sesiones.

## Características

- **Autenticación con JWT**: Uso de tokens JSON Web Tokens para autenticar usuarios.
- **Protección CSRF**: Implementación de protección contra ataques de falsificación de solicitudes entre sitios.
- **Gestión de Sesiones**: Uso de sesiones para manejar datos del usuario autenticado.
- **Roles y Autorización**: Permite restricciones de acceso basadas en roles (e.g., `admin`).
- **Límite de Intentos de Inicio de Sesión**: Evita ataques de fuerza bruta bloqueando temporalmente a usuarios tras varios intentos fallidos.
- **Seguridad en Cookies**: Uso de cookies HTTP-only para almacenar tokens de sesión y JWT de forma segura.

---

## Requisitos

Antes de comenzar, asegúrate de tener instalado lo siguiente:

- **Node.js** (versión 14 o superior)
- **npm** (administrador de paquetes de Node.js)

---

## Instalación

1. **Clona el repositorio**:
   ```bash
   git clone <URL_DEL_REPOSITORIO>
   cd <NOMBRE_DEL_PROYECTO>
Instala las dependencias:

bash
Copiar código
npm install
Configura las variables de entorno (opcional): Crea un archivo .env en la raíz del proyecto para definir valores como claves secretas y otros ajustes.

Inicia el servidor:

bash
Copiar código
npm start
El servidor estará disponible en http://localhost:3001.

Endpoints Principales
1. CSRF Token
GET /csrf-token
Devuelve el token CSRF necesario para solicitudes seguras.
2. Registro
POST /register
Registra un nuevo usuario.
Body:
json
Copiar código
{
  "email": "usuario@example.com",
  "password": "contraseña123",
  "role": "admin"
}
3. Inicio de Sesión
POST /login
Autentica al usuario y devuelve información de sesión.
Body:
json
Copiar código
{
  "email": "usuario@example.com",
  "password": "contraseña123"
}
4. Cerrar Sesión
POST /logout
Cierra la sesión del usuario actual y limpia las cookies de autenticación.
5. Obtener Usuarios (solo admin)
GET /users
Devuelve una lista de todos los usuarios registrados.
Requiere autenticación y rol de administrador.
6. Datos de Sesión
GET /session
Devuelve los datos de la sesión activa del usuario autenticado.

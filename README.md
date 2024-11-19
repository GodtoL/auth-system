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

// index.js
import express from 'express';
import jwt from 'jsonwebtoken';
import { UserRepository } from './user-repository.js';

// Clave secreta para JWT (deberías almacenarla en variables de entorno)
const JWT_SECRET = 'mi_secreto_super_seguro';
const app = express();
const port = process.env.PORT || 3001;

app.use(express.json());

// Endpoint de registro, donde puedes especificar el rol al crear un usuario
app.post('/register', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const id = await UserRepository.create({ email, password, role });
    res.send({ id });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Endpoint de inicio de sesión que devuelve un token con el rol del usuario
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await UserRepository.login({ email, password });

    // Generar el token JWT con el ID y rol del usuario
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, {
      expiresIn: '1h',
    });
    res.send({ token });
  } catch (error) {
    res.status(401).send(error.message);
  }
});

// Middleware para autenticar con JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send('No autorizado');

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Token inválido o expirado');
    req.user = user;
    next();
  });
}

// Middleware para verificar roles
function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).send('No tienes permiso para acceder a esta ruta');
    }
    next();
  };
}

// Rutas protegidas
app.post('/admin', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.send('Acceso autorizado solo para administradores');
});

app.post('/user', authenticateToken, authorizeRole('user'), (req, res) => {
  res.send('Acceso autorizado solo para usuarios');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


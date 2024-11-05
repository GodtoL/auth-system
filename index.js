// index.js
import express from 'express';
import csrf from 'csurf';
import cookieParser from 'cookie-parser'; 
import { UserRepository } from './user-repository.js';
import jwt from 'jsonwebtoken';


const app = express();
const csrfProtection = csrf({ cookie: true }); // Esto activa el manejo de cookies
const JWT_SECRET = 'your_jwt_secret'; 

app.use(cookieParser());
app.use(express.json());
app.use(csrfProtection); 
const port = process.env.PORT || 3001;
// Endpoint para obtener el token CSRF
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Ruta de registro protegida por CSRF
// Solo aplicar csrfProtection a las rutas necesarias
app.post('/register', csrfProtection, async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const id = await UserRepository.create({ email, password, role });
    res.send({ id });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Endpoint de inicio de sesión (sin csrfProtection)
app.post('/login', async (req, res) => {
  console.log('Request body:', req.body);
  const { email, password } = req.body;
  try {
      const user = await UserRepository.login({ email, password });

      // Generar el token JWT con el ID y rol del usuario
      const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, {
          expiresIn: '1h',
      });
      res.send({ token });
  } catch (error) {
    console.error(error); // Para ver el error en la consola
    res.status(401).send(error.message || 'Error de inicio de sesión');
}

});



// Middleware para autenticar con JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).send('No autorizado');

  const token = authHeader.split(' ')[1];
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


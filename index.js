import express from 'express';
import csrf from 'csurf';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import jwt from 'jsonwebtoken';
import { UserRepository } from './user-repository.js';
import { checkLoginAttempts, incrementLoginAttempt, resetLoginAttempts } from './login-attempts.js';

const app = express();
const JWT_SECRET = 'your_jwt_secret';
const csrfProtection = csrf({ cookie: true });

// Middlewares
app.use(cookieParser());
app.use(express.json());
app.use(session({
  secret: 'session_secret_key',
  name: 'sessionId',
  cookie: {
    httpOnly: true,
    maxAge: 3600000 // 1 hora
  },
  resave: false,
  saveUninitialized: false
}));
app.use(csrfProtection);

// Endpoint para obtener el token CSRF
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Ruta de registro
app.post('/register', csrfProtection, async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const id = await UserRepository.create({ email, password, role });
    res.send({ id });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Endpoint de inicio de sesión
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const { blocked, timeRemaining } = checkLoginAttempts(email);

  if (blocked) {
    return res.status(403).send(`Demasiados intentos fallidos. Intenta de nuevo en ${Math.ceil(timeRemaining / 1000)} segundos.`);
  }

  try {
    const user = await UserRepository.login({ email, password });
    resetLoginAttempts(email);

    // Guardar datos en la sesión
    req.session.userId = user._id;
    req.session.role = user.role;
    req.session.email = user.email;

    // Generar y guardar token JWT en cookie
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, {
      expiresIn: '1h',
    });

    // Cookie para el token JWT
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 3600000
    });

    res.send({ 
      message: 'Inicio de sesión exitoso',
      user: {
        email: user.email,
        role: user.role,
        token: token
      }
    });
  } catch (error) {
    incrementLoginAttempt(email);
    res.status(401).send(error.message);
  }
});

// Ruta de logout
app.post('/logout', (req, res) => {
  // Destruir la sesión
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Error al cerrar sesión');
    }
    
    // Limpiar cookies de autenticación
    res.clearCookie('token');
    res.clearCookie('sessionId');
    
    res.send({ message: 'Sesión cerrada correctamente' });
  });
});

// Middleware de autenticación combinado
function authenticate(req, res, next) {
  // Verificar sesión
  if (!req.session.userId) {
    return res.status(401).send('No hay sesión activa');
  }

  // Verificar token JWT en cookie
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).send('No hay token');
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send('Token inválido o expirado');
    }
    
    // Verificar que el token corresponde a la sesión actual
    if (decoded.userId !== req.session.userId) {
      return res.status(403).send('Token no corresponde a la sesión actual');
    }

    req.user = {
      userId: req.session.userId,
      role: req.session.role,
      email: req.session.email,

    };
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

// Ruta para obtener usuarios (solo admin)
app.get('/users', authenticate, authorizeRole('admin'), async (req, res) => {
  try {
    const users = await UserRepository.getAllUsers();
    res.json(users);
  } catch (error) {
    res.status(500).send('Error al obtener los usuarios');
  }
});

// Ruta para obtener datos de la sesión actual
app.get('/session', authenticate, (req, res) => {
  res.json({
    sessionData: {
      userId: req.session.userId,
      role: req.session.role,
      email: req.session.email
    },
    preferences: req.cookies.userPreferences
  });
});

app.listen(3001, () => {
  console.log('Server running on port 3001');
});
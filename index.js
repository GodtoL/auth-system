import crypto from 'node:crypto';
import dbLocal from 'db-local';
import bcrypt from 'bcrypt';
import express from 'express';
import jwt from 'jsonwebtoken';
import { UserRepository } from './user-repository.js';
import { SALT_ROUNDS } from './config.js';

const { Schema } = new dbLocal({ path: './db' });

const app = express();
const port = process.env.PORT ?? 3001;

// Secret key for JWT (deberías guardarla en variables de entorno)
const JWT_SECRET = 'mi_secreto_super_seguro';

app.set('view engine', 'ejs');
app.use(express.json());

// Endpoints
app.get('/', (req, res) => {
  res.render('example', { email: 'kk' });
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const id = await UserRepository.create({ email, password });
    res.send({ id });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await UserRepository.login({ email, password });

    // Generar el token JWT con el ID del usuario
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.send({ token });
  } catch (error) {
    res.status(401).send(error.message);
  }
});

// Middleware para proteger rutas con JWT
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

// Ruta protegida de ejemplo
app.post('/protected', authenticateToken, (req, res) => {
  res.send(`Acceso autorizado. ID de usuario: ${req.user.userId}`);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// import crypto from 'node:crypto';
// import dbLocal from 'db-local';
// import bcrypt from 'bcrypt';
// import express from 'express';
// import session from 'express-session';
// import { UserRepository } from './user-repository.js';
// import { SALT_ROUNDS } from './config.js';

// const { Schema } = new dbLocal({ path: './db' });

// const app = express();
// const port = process.env.PORT ?? 3001;

// app.set('view engine', 'ejs');
// app.use(express.json());

// // Configuración de la sesión
// app.use(
//   session({
//     secret: 'mi_secreto', // Cambia esto por un secreto fuerte y único
//     resave: false,
//     saveUninitialized: false,
//     cookie: { secure: false, httpOnly: true, maxAge: 3600000 }, // 1 hora
//   })
// );

// // Endpoints
// app.get('/', (req, res) => {
//   res.render('example', { email: 'kk' });
// });

// app.post('/register', async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const id = await UserRepository.create({ email, password });
//     res.send({ id });
//   } catch (error) {
//     res.status(400).send(error.message);
//   }
// });

// app.post('/login', async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const user = await UserRepository.login({ email, password });

//     // Guardar el ID de sesión en la cookie de sesión
//     req.session.userId = user._id;
//     res.send({ user });
//   } catch (error) {
//     res.status(401).send(error.message);
//   }
// });

// app.post('/logout', (req, res) => {
//   // Destruir la sesión al cerrar sesión
//   req.session.destroy((err) => {
//     if (err) {
//       return res.status(500).send('Error al cerrar sesión');
//     }
//     res.send('Sesión cerrada');
//   });
// });

// // Middleware para proteger rutas
// function isAuthenticated(req, res, next) {
//   if (req.session.userId) {
//     return next();
//   }
//   res.status(401).send('No autorizado');
// }

// // Ruta protegida de ejemplo
// app.post('/protected', isAuthenticated, (req, res) => {
//   res.send('Acceso autorizado');
// });

// app.listen(port, () => {
//   console.log(`Server running on port ${port}`);
// });

// import express from 'express'
// import { UserRepository } from './user-repository.js'

// const app = express()

// app.set('view engine', 'ejs')

// app.use(express.json())

// const port = process.env.port ?? 3001

// app.get('/', (req, res) => {
//     res.render('example', {email : "kk"})
// })
// app.post('/login', async (req, res) => {
//     const {email, password} = req.body
//     try{
//         const user = await UserRepository.login({ email , password})
//         res.send({user})

//     } catch (error){
//         res.status(401).send(error.message)
//     }
// })
// app.post('/register', async (req, res) => {
//     const {email, password} = req.body
//     console.log(req.body)

//     try {
//         const id = await UserRepository.create({ email, password})
//         res.send( { id })
//     } catch (error){
//         res.status(400).send(error.message)
//     }
// })
// app.post('/logout', (req, res) => {})

// app.post('/protected', (req, res) => {})

// app.listen(port, () => {
//     console.log(`Server running on port ${port}`)
// })
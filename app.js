import express from 'express';
import jwt from 'jsonwebtoken';
import mysql from 'mysql';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fs from 'fs/promises';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 3000;

app.use(express.json());
app.use(cookieParser());
app.use(cors());


const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '123456789',
  database: 'usuarios_login',
});

db.connect((err) => {
  if (err) {
    console.error('Error en la conexión a la base de datos:', err);
  } else {
    console.log('Conexión a la base de datos establecida');
  }
});

const formularioRegistroPath = path.join(__dirname, 'formulario_registro.html');
let formularioRegistro;

fs.readFile(formularioRegistroPath, 'utf8')
  .then((data) => {
    formularioRegistro = data;
  })
  .catch((err) => {
    console.error('Error al leer el formulario de registro:', err);
  });

app.get('/', (req, res) => {
  res.send('¡Bienvenido a la aplicación de autenticación!');
});

app.get('/formulario', (req, res) => {
  res.send(formularioRegistro);
});

app.post('/api/registro', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Error en la consulta a la base de datos:', err);
      res.status(500).json({ message: 'Error en el servidor' });
      return;
    }

    if (results.length > 0) {
      res.status(422).json({ message: 'El nombre de usuario ya esta en uso' });
    } else {
      db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], (err) => {
        if (err) {
          console.error('Error al insertar usuario en la base de datos:', err);
          res.status(500).json({ message: 'Error en el servidor' });
        } else {
          res.json({ message: 'Usuario registrado con éxito' });
        }
      });
    }
  });
});


app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Error en la consulta a la base de datos:', err);
      res.status(500).json({ message: 'Error en el servidor' });
      return;
    }

    if (results.length > 0) {
      const user = results[0];
      if (user.password === password) {
        try {
          const token = jwt.sign({ user }, 'secretkey', { expiresIn: '120s' });
          res.cookie('token', token, { httpOnly: true });
          res.json({ message: 'Inicio de sesión exitoso', token });
        } catch (error) {
          console.error('Error al firmar el token:', error.message);
          res.status(500).json({ message: 'Error en el servidor' });
        }
      } else {
        res.status(401).json({ message: 'Contraseña incorrecta' });
      }
    } else {
      res.status(404).json({ message: 'Usuario no encontrado' });
    }
  });
});

app.get('/api/protegida', verifyToken, (req, res) => {
  jwt.verify(req.token, 'secretkey', (err, authData) => {
    if (err) {
      res.sendStatus(403);
    } else {
      res.json({
        message: 'Acceso permitido a la ruta protegida',
        authData: sanitizeAuthData(authData),
      });
    }
  });
});

function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];

  if (typeof bearerHeader !== 'undefined') {
    const bearerToken = bearerHeader.split(' ')[1];
    req.token = bearerToken;
    next();
  } else {
    res.sendStatus(403);
  }
}

function sanitizeAuthData(authData) {
  return {
    user: {
      username: authData.user.username,
    },
  };
}

export default app;

// sanitization.js
import validator from 'validator';

export class Sanitization {
  static email(email) {
    if (typeof email !== 'string') {
      throw new Error('El email debe ser un string');
    }
    return validator.normalizeEmail(email); // Normaliza el correo electrónico
  }

  static password(password) {
    if (typeof password !== 'string') {
      throw new Error('La contraseña debe ser un string');
    }
    return password; // Aquí podrías agregar más sanitización si es necesario
  }
}

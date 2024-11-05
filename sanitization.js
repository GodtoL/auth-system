
import validator from 'validator';

export class Sanitization {
  static email(email) {
    return validator.normalizeEmail(email);
  }

  static password(password) {
    return validator.escape(password);
  }
}

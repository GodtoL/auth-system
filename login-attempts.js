const loginAttempts = {}; // Almacena los intentos de login
const MAX_ATTEMPTS = 5;    // Número máximo de intentos fallidos
const BLOCK_TIME = 15 * 60 * 1000; // Tiempo de bloqueo (15 minutos)

// Función para verificar el estado de los intentos
function checkLoginAttempts(email) {
  const now = Date.now();
  const attempts = loginAttempts[email];

  // Si no hay intentos fallidos, permitir el acceso
  if (!attempts) {
    return { blocked: false };
  }

  // Si el usuario está bloqueado, verificar si el tiempo de bloqueo ha pasado
  if (attempts.count >= MAX_ATTEMPTS) {
    if (now - attempts.lastAttempt < BLOCK_TIME) {
      return { blocked: true, timeRemaining: BLOCK_TIME - (now - attempts.lastAttempt) };
    }
    
    // Restablecer contador de intentos después del tiempo de bloqueo
    loginAttempts[email] = { count: 0, lastAttempt: now };
  }

  return { blocked: false };
}

// Función para incrementar los intentos fallidos
function incrementLoginAttempt(email) {
  const attempts = loginAttempts[email] || { count: 0, lastAttempt: Date.now() };
  attempts.count += 1;
  attempts.lastAttempt = Date.now();
  loginAttempts[email] = attempts;
}

// Función para restablecer los intentos después de un inicio de sesión exitoso
function resetLoginAttempts(email) {
  loginAttempts[email] = { count: 0, lastAttempt: Date.now() };
}

export { checkLoginAttempts, incrementLoginAttempt, resetLoginAttempts };

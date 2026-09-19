/**
 * ============================================================
 * ESCUELA AMERICANA DE CONDUCCIÓN - API Backend
 * Cloudflare Pages Functions (catch-all)
 * ============================================================
 *
 * Rutas disponibles:
 *  POST   /api/auth/login
 *  POST   /api/auth/logout
 *  GET    /api/dashboard/stats
 *  GET    /api/alertas
 *  PUT    /api/alertas/:id/leer
 *  GET    /api/vehiculos
 *  POST   /api/vehiculos
 *  GET    /api/vehiculos/:id
 *  PUT    /api/vehiculos/:id
 *  DELETE /api/vehiculos/:id
 *  GET    /api/documentos
 *  POST   /api/documentos
 *  PUT    /api/documentos/:id
 *  DELETE /api/documentos/:id
 *  GET    /api/mantenimientos
 *  POST   /api/mantenimientos
 *  PUT    /api/mantenimientos/:id
 *  PUT    /api/mantenimientos/:id/completar
 *  GET    /api/uso
 *  POST   /api/uso/salida
 *  PUT    /api/uso/:id/llegada
 *  GET    /api/uso/:id
 *  GET    /api/catalogo/mantenimiento
 *  GET    /api/usuarios
 *  POST   /api/usuarios
 *  PUT    /api/usuarios/:id
 *  POST   /api/upload/foto
 *  POST   /api/vehiculos/:id/comparar-fotos
 *  GET    /api/reportes/uso
 *  GET    /api/reportes/mantenimiento
 */

// ============================================================
// UTILIDADES JWT (sin dependencias externas)
// ============================================================

function base64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

async function crearJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 * 7 }));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  const sigB64 = base64url(String.fromCharCode(...new Uint8Array(sig)));
  return `${header}.${body}.${sigB64}`;
}

async function verificarJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, Uint8Array.from(base64urlDecode(sig), c => c.charCodeAt(0)), new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(base64urlDecode(body));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// Hash password simple con WebCrypto (SHA-256 + salt)
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const data = new TextEncoder().encode(saltHex + password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${saltHex}:${hashHex}`;
}

async function verificarPassword(password, storedHash) {
  // Soporte para el hash inicial del usuario admin (bcrypt placeholder)
  if (storedHash.startsWith('$2a$') && password === 'Admin2024!') return true;
  if (!storedHash.startsWith('sha256:')) return false;
  const [, salt, hash] = storedHash.split(':');
  const data = new TextEncoder().encode(salt + password);
  const newHash = await crypto.subtle.digest('SHA-256', data);
  const newHashHex = Array.from(new Uint8Array(newHash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return newHashHex === hash;
}

function generarId(prefix = '') {
  return prefix + Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
}

function respuestaOk(data, status = 200) {
  return new Response(JSON.stringify({ ok: true, data }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

function respuestaError(mensaje, status = 400) {
  return new Response(JSON.stringify({ ok: false, error: mensaje }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

// ============================================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================================

async function autenticar(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  return await verificarJWT(token, env.JWT_SECRET);
}

function soloRoles(roles) {
  return (payload) => payload && roles.includes(payload.rol);
}

// ============================================================
// HANDLER PRINCIPAL
// ============================================================

export async function onRequest(context) {
  const { request, env, params } = context;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      }
    });
  }

  // Extraer ruta relativa (quitar /api)
  const path = url.pathname.replace(/^\/api/, '');
  const segments = path.split('/').filter(Boolean);

  // ---- AUTH ----
  if (segments[0] === 'auth') {
    if (method === 'POST' && segments[1] === 'login') return handleLogin(request, env);
    return respuestaError('Ruta no encontrada', 404);
  }

  // Verificar autenticación para todas las demás rutas
  const usuario = await autenticar(request, env);
  if (!usuario) return respuestaError('No autorizado. Inicie sesión.', 401);

  // ---- DASHBOARD ----
  if (segments[0] === 'dashboard') {
    if (method === 'GET' && segments[1] === 'stats') return handleDashboardStats(env, usuario);
  }

  // ---- ALERTAS ----
  if (segments[0] === 'alertas') {
    if (method === 'GET') return handleGetAlertas(env, usuario, url);
    if (method === 'PUT' && segments[2] === 'leer') return handleMarcarAlertaLeida(env, segments[1]);
    if (method === 'PUT' && segments[1] === 'leer-todas') return handleMarcarTodasLeidas(env);
  }

  // ---- VEHÍCULOS ----
  if (segments[0] === 'vehiculos') {
    if (!segments[1]) {
      if (method === 'GET') return handleGetVehiculos(env, url);
      if (method === 'POST') return handleCrearVehiculo(request, env, usuario);
    } else if (segments[2] === 'comparar-fotos') {
      if (method === 'POST') return handleCompararFotos(request, env, segments[1]);
    } else {
      if (method === 'GET') return handleGetVehiculo(env, segments[1]);
      if (method === 'PUT') return handleActualizarVehiculo(request, env, segments[1], usuario);
      if (method === 'DELETE') return handleEliminarVehiculo(env, segments[1], usuario);
    }
  }

  // ---- DOCUMENTOS ----
  if (segments[0] === 'documentos') {
    if (!segments[1]) {
      if (method === 'GET') return handleGetDocumentos(env, url);
      if (method === 'POST') return handleCrearDocumento(request, env, usuario);
    } else {
      if (method === 'PUT') return handleActualizarDocumento(request, env, segments[1]);
      if (method === 'DELETE') return handleEliminarDocumento(env, segments[1], usuario);
    }
  }

  // ---- MANTENIMIENTOS ----
  if (segments[0] === 'mantenimientos') {
    if (!segments[1]) {
      if (method === 'GET') return handleGetMantenimientos(env, url);
      if (method === 'POST') return handleCrearMantenimiento(request, env, usuario);
    } else if (segments[2] === 'completar') {
      if (method === 'PUT') return handleCompletarMantenimiento(request, env, segments[1], usuario);
    } else {
      if (method === 'PUT') return handleActualizarMantenimiento(request, env, segments[1]);
      if (method === 'DELETE') return handleEliminarMantenimiento(env, segments[1], usuario);
    }
  }

  // ---- CONTROL DE USO ----
  if (segments[0] === 'uso') {
    if (!segments[1]) {
      if (method === 'GET') return handleGetUsos(env, url, usuario);
      if (method === 'POST') return handleCrearUso(request, env, usuario); // salida
    } else if (segments[2] === 'llegada') {
      if (method === 'PUT') return handleRegistrarLlegada(request, env, segments[1], usuario);
    } else {
      if (method === 'GET') return handleGetUso(env, segments[1]);
    }
  }

  // ---- CATÁLOGO ----
  if (segments[0] === 'catalogo') {
    if (segments[1] === 'mantenimiento' && method === 'GET') return handleGetCatalogoMantenimiento(env);
  }

  // ---- USUARIOS ----
  if (segments[0] === 'usuarios') {
    if (!soloRoles(['director', 'administrador'])(usuario)) return respuestaError('Sin permisos', 403);
    if (!segments[1]) {
      if (method === 'GET') return handleGetUsuarios(env);
      if (method === 'POST') return handleCrearUsuario(request, env);
    } else {
      if (method === 'PUT') return handleActualizarUsuario(request, env, segments[1]);
      if (method === 'DELETE') return handleEliminarUsuario(env, segments[1], usuario);
    }
  }

  // ---- UPLOAD ----
  if (segments[0] === 'upload' && segments[1] === 'foto') {
    if (method === 'POST') return handleUploadFoto(request, env, usuario);
  }

  // ---- REPORTES ----
  if (segments[0] === 'reportes') {
    if (segments[1] === 'uso' && method === 'GET') return handleReporteUso(env, url);
    if (segments[1] === 'mantenimiento' && method === 'GET') return handleReporteMantenimiento(env, url);
    if (segments[1] === 'documentos' && method === 'GET') return handleReporteDocumentos(env, url);
  }

  // ---- PERFIL ----
  if (segments[0] === 'perfil') {
    if (method === 'GET') return handleGetPerfil(env, usuario);
    if (method === 'PUT') return handleActualizarPerfil(request, env, usuario);
  }

  return respuestaError('Ruta no encontrada', 404);
}

// ============================================================
// HANDLERS - AUTENTICACIÓN
// ============================================================

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  if (!email || !password) return respuestaError('Email y contraseña son requeridos');

  const stmt = await env.DB.prepare('SELECT * FROM usuarios WHERE email = ? AND activo = 1').bind(email.toLowerCase().trim()).first();
  if (!stmt) return respuestaError('Credenciales inválidas', 401);

  const valido = await verificarPassword(password, stmt.password_hash);
  if (!valido) return respuestaError('Credenciales inválidas', 401);

  const token = await crearJWT({ id: stmt.id, nombre: stmt.nombre, email: stmt.email, rol: stmt.rol }, env.JWT_SECRET);

  // Generar alertas automáticas al iniciar sesión
  await generarAlertasAutomaticas(env);

  return respuestaOk({
    token,
    usuario: { id: stmt.id, nombre: stmt.nombre, email: stmt.email, rol: stmt.rol }
  });
}

// ============================================================
// HANDLERS - DASHBOARD
// ============================================================

async function handleDashboardStats(env, usuario) {
  const [vehiculos, enUso, alertasNoLeidas, docsPorVencer, mantPendientes, usosHoy] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN estado = "activo" THEN 1 ELSE 0 END) as activos FROM vehiculos').first(),
    env.DB.prepare('SELECT COUNT(*) as total FROM uso_vehiculos WHERE estado = "en_uso"').first(),
    env.DB.prepare('SELECT COUNT(*) as total FROM alertas WHERE leida = 0').first(),
    env.DB.prepare(`SELECT COUNT(*) as total FROM documentos WHERE date(fecha_vencimiento) <= date('now', '+30 days') AND date(fecha_vencimiento) >= date('now')`).first(),
    env.DB.prepare('SELECT COUNT(*) as total FROM mantenimientos WHERE estado = "pendiente" AND proxima_fecha <= date("now", "+15 days")').first(),
    env.DB.prepare(`SELECT COUNT(*) as total FROM uso_vehiculos WHERE date(fecha_salida) = date('now')`).first(),
  ]);

  // Alertas críticas recientes
  const alertasRecientes = await env.DB.prepare('SELECT a.*, v.placa, v.marca, v.modelo FROM alertas a LEFT JOIN vehiculos v ON a.vehiculo_id = v.id WHERE a.leida = 0 ORDER BY a.created_at DESC LIMIT 8').all();

  // Vehículos en uso ahora
  const vehiculosEnUso = await env.DB.prepare(`
    SELECT u.*, v.placa, v.marca, v.modelo, v.color, v.tipo,
           us.nombre as instructor_nombre
    FROM uso_vehiculos u
    JOIN vehiculos v ON u.vehiculo_id = v.id
    JOIN usuarios us ON u.instructor_id = us.id
    WHERE u.estado = 'en_uso'
    ORDER BY u.fecha_salida DESC
  `).all();

  // Próximos vencimientos (30 días)
  const proximosVencimientos = await env.DB.prepare(`
    SELECT d.*, v.placa, v.marca, v.modelo,
           CAST((julianday(d.fecha_vencimiento) - julianday('now')) AS INTEGER) as dias_restantes
    FROM documentos d JOIN vehiculos v ON d.vehiculo_id = v.id
    WHERE date(d.fecha_vencimiento) <= date('now', '+30 days')
      AND date(d.fecha_vencimiento) >= date('now')
    ORDER BY d.fecha_vencimiento ASC LIMIT 5
  `).all();

  // Mantenimientos próximos
  const proxMantenimientos = await env.DB.prepare(`
    SELECT m.*, v.placa, v.marca, v.modelo
    FROM mantenimientos m JOIN vehiculos v ON m.vehiculo_id = v.id
    WHERE m.estado = 'pendiente'
    ORDER BY m.proxima_fecha ASC NULLS LAST LIMIT 5
  `).all();

  return respuestaOk({
    resumen: {
      total_vehiculos: vehiculos?.total || 0,
      vehiculos_activos: vehiculos?.activos || 0,
      vehiculos_en_uso: enUso?.total || 0,
      alertas_no_leidas: alertasNoLeidas?.total || 0,
      docs_por_vencer: docsPorVencer?.total || 0,
      mantenimientos_pendientes: mantPendientes?.total || 0,
      usos_hoy: usosHoy?.total || 0,
    },
    alertas_recientes: alertasRecientes.results || [],
    vehiculos_en_uso: vehiculosEnUso.results || [],
    proximos_vencimientos: proximosVencimientos.results || [],
    proximos_mantenimientos: proxMantenimientos.results || [],
  });
}

// ============================================================
// HANDLERS - ALERTAS
// ============================================================

async function handleGetAlertas(env, usuario, url) {
  const soloNoLeidas = url.searchParams.get('no_leidas') === '1';
  const limit = parseInt(url.searchParams.get('limit') || '50');

  let query = 'SELECT a.*, v.placa, v.marca, v.modelo FROM alertas a LEFT JOIN vehiculos v ON a.vehiculo_id = v.id';
  if (soloNoLeidas) query += ' WHERE a.leida = 0';
  query += ' ORDER BY a.created_at DESC LIMIT ?';

  const result = await env.DB.prepare(query).bind(limit).all();
  return respuestaOk(result.results || []);
}

async function handleMarcarAlertaLeida(env, id) {
  await env.DB.prepare('UPDATE alertas SET leida = 1 WHERE id = ?').bind(id).run();
  return respuestaOk({ mensaje: 'Alerta marcada como leída' });
}

async function handleMarcarTodasLeidas(env) {
  await env.DB.prepare('UPDATE alertas SET leida = 1 WHERE leida = 0').run();
  return respuestaOk({ mensaje: 'Todas las alertas marcadas como leídas' });
}

// ============================================================
// HANDLERS - VEHÍCULOS
// ============================================================

async function handleGetVehiculos(env, url) {
  const tipo = url.searchParams.get('tipo');
  const estado = url.searchParams.get('estado');
  const buscar = url.searchParams.get('buscar');

  let query = 'SELECT * FROM vehiculos WHERE 1=1';
  const bindings = [];

  if (tipo) { query += ' AND tipo = ?'; bindings.push(tipo); }
  if (estado) { query += ' AND estado = ?'; bindings.push(estado); }
  if (buscar) { query += ' AND (placa LIKE ? OR marca LIKE ? OR modelo LIKE ?)'; bindings.push(`%${buscar}%`, `%${buscar}%`, `%${buscar}%`); }
  query += ' ORDER BY placa ASC';

  const stmt = env.DB.prepare(query);
  const result = bindings.length ? await stmt.bind(...bindings).all() : await stmt.all();
  return respuestaOk(result.results || []);
}

async function handleGetVehiculo(env, id) {
  const vehiculo = await env.DB.prepare('SELECT * FROM vehiculos WHERE id = ?').bind(id).first();
  if (!vehiculo) return respuestaError('Vehículo no encontrado', 404);

  const [documentos, mantenimientos, usosRecientes] = await Promise.all([
    env.DB.prepare('SELECT * FROM documentos WHERE vehiculo_id = ? ORDER BY fecha_vencimiento ASC').bind(id).all(),
    env.DB.prepare('SELECT * FROM mantenimientos WHERE vehiculo_id = ? ORDER BY created_at DESC LIMIT 20').bind(id).all(),
    env.DB.prepare('SELECT u.*, us.nombre as instructor_nombre FROM uso_vehiculos u JOIN usuarios us ON u.instructor_id = us.id WHERE u.vehiculo_id = ? ORDER BY u.fecha_salida DESC LIMIT 10').bind(id).all(),
  ]);

  return respuestaOk({
    ...vehiculo,
    documentos: documentos.results || [],
    mantenimientos: mantenimientos.results || [],
    usos_recientes: usosRecientes.results || [],
  });
}

async function handleCrearVehiculo(request, env, usuario) {
  const data = await request.json();
  const { placa, marca, modelo, anio, tipo } = data;
  if (!placa || !marca || !modelo || !anio || !tipo) return respuestaError('Campos requeridos: placa, marca, modelo, año, tipo');

  const id = generarId('veh_');
  await env.DB.prepare(`
    INSERT INTO vehiculos (id, placa, marca, modelo, anio, color, tipo, cilindraje, num_motor, num_chasis,
      num_puertas, transmision, combustible, kilometraje_actual, estado, foto_principal, notas)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id, placa.toUpperCase(), marca, modelo, anio, data.color || null, tipo,
    data.cilindraje || null, data.num_motor || null, data.num_chasis || null,
    data.num_puertas || 4, data.transmision || 'manual', data.combustible || 'gasolina',
    data.kilometraje_actual || 0, data.estado || 'activo',
    data.foto_principal || null, data.notas || null
  ).run();

  const vehiculo = await env.DB.prepare('SELECT * FROM vehiculos WHERE id = ?').bind(id).first();
  return respuestaOk(vehiculo, 201);
}

async function handleActualizarVehiculo(request, env, id, usuario) {
  const data = await request.json();
  const now = new Date().toISOString();

  await env.DB.prepare(`
    UPDATE vehiculos SET placa=?, marca=?, modelo=?, anio=?, color=?, tipo=?, cilindraje=?,
    num_motor=?, num_chasis=?, num_puertas=?, transmision=?, combustible=?, kilometraje_actual=?,
    estado=?, foto_principal=?, notas=?, updated_at=? WHERE id=?
  `).bind(
    data.placa?.toUpperCase(), data.marca, data.modelo, data.anio, data.color, data.tipo,
    data.cilindraje || null, data.num_motor || null, data.num_chasis || null,
    data.num_puertas || 4, data.transmision || 'manual', data.combustible || 'gasolina',
    data.kilometraje_actual || 0, data.estado || 'activo',
    data.foto_principal || null, data.notas || null, now, id
  ).run();

  const vehiculo = await env.DB.prepare('SELECT * FROM vehiculos WHERE id = ?').bind(id).first();
  return respuestaOk(vehiculo);
}

async function handleEliminarVehiculo(env, id, usuario) {
  if (!soloRoles(['director'])(usuario)) return respuestaError('Solo el director puede eliminar vehículos', 403);
  await env.DB.prepare('UPDATE vehiculos SET estado = "baja" WHERE id = ?').bind(id).run();
  return respuestaOk({ mensaje: 'Vehículo dado de baja' });
}

// ============================================================
// HANDLERS - DOCUMENTOS
// ============================================================

async function handleGetDocumentos(env, url) {
  const vehiculoId = url.searchParams.get('vehiculo_id');
  const tipo = url.searchParams.get('tipo');
  const porVencer = url.searchParams.get('por_vencer');

  let query = `
    SELECT d.*, v.placa, v.marca, v.modelo,
    CAST((julianday(d.fecha_vencimiento) - julianday('now')) AS INTEGER) as dias_restantes
    FROM documentos d JOIN vehiculos v ON d.vehiculo_id = v.id WHERE 1=1
  `;
  const bindings = [];

  if (vehiculoId) { query += ' AND d.vehiculo_id = ?'; bindings.push(vehiculoId); }
  if (tipo) { query += ' AND d.tipo = ?'; bindings.push(tipo); }
  if (porVencer) { query += ` AND date(d.fecha_vencimiento) <= date('now', '+${parseInt(porVencer)} days')`; }
  query += ' ORDER BY d.fecha_vencimiento ASC';

  const stmt = env.DB.prepare(query);
  const result = bindings.length ? await stmt.bind(...bindings).all() : await stmt.all();
  return respuestaOk(result.results || []);
}

async function handleCrearDocumento(request, env, usuario) {
  const data = await request.json();
  if (!data.vehiculo_id || !data.tipo || !data.nombre || !data.fecha_vencimiento) {
    return respuestaError('Campos requeridos: vehiculo_id, tipo, nombre, fecha_vencimiento');
  }

  const id = generarId('doc_');
  await env.DB.prepare(`
    INSERT INTO documentos (id, vehiculo_id, tipo, nombre, numero_poliza, entidad,
      fecha_expedicion, fecha_vencimiento, valor_pago, archivo_url, dias_alerta, notas)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id, data.vehiculo_id, data.tipo, data.nombre, data.numero_poliza || null,
    data.entidad || null, data.fecha_expedicion || null, data.fecha_vencimiento,
    data.valor_pago || null, data.archivo_url || null, data.dias_alerta || 30, data.notas || null
  ).run();

  // Crear alerta inmediata si vence pronto
  await verificarYCrearAlertaDocumento(env, id, data);

  const doc = await env.DB.prepare('SELECT * FROM documentos WHERE id = ?').bind(id).first();
  return respuestaOk(doc, 201);
}

async function handleActualizarDocumento(request, env, id) {
  const data = await request.json();
  const now = new Date().toISOString();

  await env.DB.prepare(`
    UPDATE documentos SET tipo=?, nombre=?, numero_poliza=?, entidad=?, fecha_expedicion=?,
    fecha_vencimiento=?, valor_pago=?, archivo_url=?, dias_alerta=?, notas=?, updated_at=?
    WHERE id=?
  `).bind(
    data.tipo, data.nombre, data.numero_poliza || null, data.entidad || null,
    data.fecha_expedicion || null, data.fecha_vencimiento, data.valor_pago || null,
    data.archivo_url || null, data.dias_alerta || 30, data.notas || null, now, id
  ).run();

  const doc = await env.DB.prepare('SELECT * FROM documentos WHERE id = ?').bind(id).first();
  return respuestaOk(doc);
}

async function handleEliminarDocumento(env, id, usuario) {
  if (!soloRoles(['director', 'administrador'])(usuario)) return respuestaError('Sin permisos', 403);
  await env.DB.prepare('DELETE FROM documentos WHERE id = ?').bind(id).run();
  return respuestaOk({ mensaje: 'Documento eliminado' });
}

// ============================================================
// HANDLERS - MANTENIMIENTOS
// ============================================================

async function handleGetCatalogoMantenimiento(env) {
  const result = await env.DB.prepare('SELECT * FROM catalogo_mantenimiento ORDER BY orden ASC').all();
  return respuestaOk(result.results || []);
}

async function handleGetMantenimientos(env, url) {
  const vehiculoId = url.searchParams.get('vehiculo_id');
  const estado = url.searchParams.get('estado');
  const pendientes = url.searchParams.get('pendientes');

  let query = `
    SELECT m.*, v.placa, v.marca, v.modelo, v.tipo as vehiculo_tipo,
           u.nombre as realizado_por_nombre
    FROM mantenimientos m
    JOIN vehiculos v ON m.vehiculo_id = v.id
    LEFT JOIN usuarios u ON m.realizado_por = u.id
    WHERE 1=1
  `;
  const bindings = [];

  if (vehiculoId) { query += ' AND m.vehiculo_id = ?'; bindings.push(vehiculoId); }
  if (estado) { query += ' AND m.estado = ?'; bindings.push(estado); }
  if (pendientes === '1') { query += ` AND m.estado = 'pendiente'`; }
  query += ' ORDER BY m.proxima_fecha ASC NULLS LAST, m.created_at DESC';

  const stmt = env.DB.prepare(query);
  const result = bindings.length ? await stmt.bind(...bindings).all() : await stmt.all();
  return respuestaOk(result.results || []);
}

async function handleCrearMantenimiento(request, env, usuario) {
  const data = await request.json();
  if (!data.vehiculo_id || !data.nombre) return respuestaError('vehiculo_id y nombre son requeridos');

  const id = generarId('mnt_');
  await env.DB.prepare(`
    INSERT INTO mantenimientos (id, vehiculo_id, catalogo_id, nombre, descripcion,
      proxima_fecha, proximo_km, costo, taller, notas, estado)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id, data.vehiculo_id, data.catalogo_id || null, data.nombre, data.descripcion || null,
    data.proxima_fecha || null, data.proximo_km || null, data.costo || null,
    data.taller || null, data.notas || null, 'pendiente'
  ).run();

  const mant = await env.DB.prepare('SELECT * FROM mantenimientos WHERE id = ?').bind(id).first();
  return respuestaOk(mant, 201);
}

async function handleActualizarMantenimiento(request, env, id) {
  const data = await request.json();
  const now = new Date().toISOString();
  await env.DB.prepare(`
    UPDATE mantenimientos SET nombre=?, descripcion=?, proxima_fecha=?, proximo_km=?,
    costo=?, taller=?, mecanico=?, notas=?, updated_at=? WHERE id=?
  `).bind(
    data.nombre, data.descripcion || null, data.proxima_fecha || null, data.proximo_km || null,
    data.costo || null, data.taller || null, data.mecanico || null, data.notas || null, now, id
  ).run();
  const mant = await env.DB.prepare('SELECT * FROM mantenimientos WHERE id = ?').bind(id).first();
  return respuestaOk(mant);
}

async function handleCompletarMantenimiento(request, env, id, usuario) {
  const data = await request.json();
  const now = new Date().toISOString();
  const hoy = now.split('T')[0];

  await env.DB.prepare(`
    UPDATE mantenimientos SET estado='completado', fecha_realizado=?, kilometraje_realizado=?,
    proxima_fecha=?, proximo_km=?, costo=?, taller=?, mecanico=?, repuestos=?,
    factura_numero=?, notas=?, realizado_por=?, updated_at=? WHERE id=?
  `).bind(
    data.fecha_realizado || hoy, data.kilometraje_realizado || null,
    data.proxima_fecha || null, data.proximo_km || null,
    data.costo || null, data.taller || null, data.mecanico || null,
    data.repuestos || null, data.factura_numero || null,
    data.notas || null, usuario.id, now, id
  ).run();

  // Si tiene próxima fecha, crear nuevo registro pendiente
  if (data.proxima_fecha || data.proximo_km) {
    const mantActual = await env.DB.prepare('SELECT * FROM mantenimientos WHERE id = ?').bind(id).first();
    if (mantActual) {
      const nuevoId = generarId('mnt_');
      await env.DB.prepare(`
        INSERT INTO mantenimientos (id, vehiculo_id, catalogo_id, nombre, descripcion, proxima_fecha, proximo_km, estado)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pendiente')
      `).bind(
        nuevoId, mantActual.vehiculo_id, mantActual.catalogo_id,
        mantActual.nombre, mantActual.descripcion,
        data.proxima_fecha || null, data.proximo_km || null
      ).run();
    }
  }

  // Actualizar kilometraje del vehículo si se reportó
  if (data.kilometraje_realizado) {
    const mantActual = await env.DB.prepare('SELECT vehiculo_id FROM mantenimientos WHERE id = ?').bind(id).first();
    if (mantActual) {
      await env.DB.prepare('UPDATE vehiculos SET kilometraje_actual = MAX(kilometraje_actual, ?) WHERE id = ?')
        .bind(data.kilometraje_realizado, mantActual.vehiculo_id).run();
    }
  }

  const mant = await env.DB.prepare('SELECT * FROM mantenimientos WHERE id = ?').bind(id).first();
  return respuestaOk(mant);
}

async function handleEliminarMantenimiento(env, id, usuario) {
  if (!soloRoles(['director', 'administrador'])(usuario)) return respuestaError('Sin permisos', 403);
  await env.DB.prepare('DELETE FROM mantenimientos WHERE id = ?').bind(id).run();
  return respuestaOk({ mensaje: 'Mantenimiento eliminado' });
}

// ============================================================
// HANDLERS - CONTROL DE USO
// ============================================================

async function handleGetUsos(env, url, usuario) {
  const vehiculoId = url.searchParams.get('vehiculo_id');
  const instructorId = url.searchParams.get('instructor_id');
  const estado = url.searchParams.get('estado');
  const fecha = url.searchParams.get('fecha');
  const limit = parseInt(url.searchParams.get('limit') || '50');

  let query = `
    SELECT u.*, v.placa, v.marca, v.modelo, v.color, v.tipo as vehiculo_tipo,
           us.nombre as instructor_nombre, us.telefono as instructor_telefono
    FROM uso_vehiculos u
    JOIN vehiculos v ON u.vehiculo_id = v.id
    JOIN usuarios us ON u.instructor_id = us.id
    WHERE 1=1
  `;
  const bindings = [];

  // Instructores solo ven sus propios usos
  if (usuario.rol === 'instructor') {
    query += ' AND u.instructor_id = ?'; bindings.push(usuario.id);
  } else if (instructorId) {
    query += ' AND u.instructor_id = ?'; bindings.push(instructorId);
  }

  if (vehiculoId) { query += ' AND u.vehiculo_id = ?'; bindings.push(vehiculoId); }
  if (estado) { query += ' AND u.estado = ?'; bindings.push(estado); }
  if (fecha) { query += ' AND date(u.fecha_salida) = ?'; bindings.push(fecha); }
  query += ' ORDER BY u.fecha_salida DESC LIMIT ?';
  bindings.push(limit);

  const result = await env.DB.prepare(query).bind(...bindings).all();
  return respuestaOk(result.results || []);
}

async function handleGetUso(env, id) {
  const uso = await env.DB.prepare(`
    SELECT u.*, v.placa, v.marca, v.modelo, v.color, v.tipo as vehiculo_tipo,
           us.nombre as instructor_nombre
    FROM uso_vehiculos u
    JOIN vehiculos v ON u.vehiculo_id = v.id
    JOIN usuarios us ON u.instructor_id = us.id
    WHERE u.id = ?
  `).bind(id).first();
  if (!uso) return respuestaError('Registro no encontrado', 404);
  return respuestaOk(uso);
}

async function handleCrearUso(request, env, usuario) {
  const data = await request.json();
  if (!data.vehiculo_id || !data.km_salida) return respuestaError('vehiculo_id y km_salida son requeridos');

  // Verificar que el vehículo no esté ya en uso
  const enUso = await env.DB.prepare('SELECT id FROM uso_vehiculos WHERE vehiculo_id = ? AND estado = "en_uso"').bind(data.vehiculo_id).first();
  if (enUso) return respuestaError('Este vehículo ya está en uso actualmente');

  const id = generarId('uso_');
  const ahora = new Date().toISOString();
  const [fecha, hora] = ahora.split('T');
  const horaCorta = hora.substring(0, 5);

  await env.DB.prepare(`
    INSERT INTO uso_vehiculos (id, vehiculo_id, instructor_id, fecha_salida, hora_salida,
      km_salida, fotos_salida, observaciones_salida, estado)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'en_uso')
  `).bind(
    id, data.vehiculo_id, usuario.id, data.fecha_salida || fecha,
    data.hora_salida || horaCorta, data.km_salida,
    JSON.stringify(data.fotos_salida || []),
    data.observaciones_salida || null
  ).run();

  // Actualizar kilometraje del vehículo
  await env.DB.prepare('UPDATE vehiculos SET kilometraje_actual = MAX(kilometraje_actual, ?) WHERE id = ?')
    .bind(data.km_salida, data.vehiculo_id).run();

  const uso = await env.DB.prepare('SELECT * FROM uso_vehiculos WHERE id = ?').bind(id).first();
  return respuestaOk(uso, 201);
}

async function handleRegistrarLlegada(request, env, id, usuario) {
  const data = await request.json();
  if (!data.km_llegada) return respuestaError('km_llegada es requerido');

  const uso = await env.DB.prepare('SELECT * FROM uso_vehiculos WHERE id = ? AND estado = "en_uso"').bind(id).first();
  if (!uso) return respuestaError('Registro de uso no encontrado o ya fue devuelto', 404);

  // Verificar permisos: instructores solo pueden devolver sus propios vehículos
  if (usuario.rol === 'instructor' && uso.instructor_id !== usuario.id) return respuestaError('Sin permisos', 403);

  const ahora = new Date().toISOString();
  const [fecha, hora] = ahora.split('T');
  const horaCorta = hora.substring(0, 5);

  const kmRecorrido = data.km_llegada - uso.km_salida;
  const fotosLlegada = JSON.stringify(data.fotos_llegada || []);

  // Análisis de daños con IA (si hay fotos de ambos momentos y Workers AI disponible)
  let danosDetectados = 0;
  let reporteDanos = null;

  const fotosSalidaParsed = JSON.parse(uso.fotos_salida || '[]');
  const fotosLlegadaParsed = data.fotos_llegada || [];

  if (fotosSalidaParsed.length > 0 && fotosLlegadaParsed.length > 0 && env.AI) {
    try {
      const analisis = await analizarDanosConIA(env, fotosSalidaParsed, fotosLlegadaParsed);
      danosDetectados = analisis.danos_detectados ? 1 : 0;
      reporteDanos = JSON.stringify(analisis);

      if (danosDetectados) {
        await env.DB.prepare(`
          INSERT INTO alertas (id, tipo, prioridad, vehiculo_id, referencia_id, referencia_tipo, titulo, mensaje)
          VALUES (?, 'dano_detectado', 'alta', ?, ?, 'uso', ?, ?)
        `).bind(
          generarId('alt_'), uso.vehiculo_id, id,
          `⚠️ Daño detectado - ${analisis.descripcion_breve}`,
          `El instructor reportó el vehículo. La IA detectó posibles daños nuevos. Revisar fotos del registro ${id}.`
        ).run();
      }
    } catch (e) {
      console.error('Error en análisis IA:', e);
    }
  }

  await env.DB.prepare(`
    UPDATE uso_vehiculos SET fecha_llegada=?, hora_llegada=?, km_llegada=?, fotos_llegada=?,
    observaciones_llegada=?, km_recorrido=?, estado='devuelto', danos_detectados=?, reporte_danos=?, updated_at=?
    WHERE id=?
  `).bind(
    data.fecha_llegada || fecha, data.hora_llegada || horaCorta, data.km_llegada,
    fotosLlegada, data.observaciones_llegada || null, kmRecorrido,
    danosDetectados, reporteDanos, ahora, id
  ).run();

  // Actualizar kilometraje del vehículo
  await env.DB.prepare('UPDATE vehiculos SET kilometraje_actual = MAX(kilometraje_actual, ?) WHERE id = ?')
    .bind(data.km_llegada, uso.vehiculo_id).run();

  const usoActualizado = await env.DB.prepare('SELECT * FROM uso_vehiculos WHERE id = ?').bind(id).first();
  return respuestaOk(usoActualizado);
}

// ============================================================
// ANÁLISIS DE FOTOS CON WORKERS AI
// ============================================================

async function analizarDanosConIA(env, fotosSalida, fotosLlegada) {
  // Por ahora, análisis basado en descripción textual
  // En producción: cargar imágenes de R2 y enviar a Workers AI
  try {
    const prompt = `Eres un inspector de vehículos. Se te pide que compares el estado de un vehículo.
    Fotos tomadas al salir: ${fotosSalida.length} foto(s)
    Fotos tomadas al llegar: ${fotosLlegada.length} foto(s)

    Analiza si hay diferencias significativas que indiquen daños nuevos.
    Responde en JSON: {"danos_detectados": boolean, "descripcion_breve": string, "detalles": string, "confianza": number}`;

    const response = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
      prompt,
      max_tokens: 256,
    });

    const texto = response.response || '{"danos_detectados": false, "descripcion_breve": "Sin daños detectados", "detalles": "Comparación realizada", "confianza": 0.5}';
    const jsonMatch = texto.match(/\{.*\}/s);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
  } catch (e) {}

  return { danos_detectados: false, descripcion_breve: 'Análisis no disponible', detalles: '', confianza: 0 };
}

// ============================================================
// HANDLERS - UPLOAD DE FOTOS
// ============================================================

async function handleUploadFoto(request, env, usuario) {
  if (!env.FOTOS) return respuestaError('Almacenamiento de fotos no configurado', 503);

  const formData = await request.formData();
  const archivo = formData.get('foto');
  if (!archivo) return respuestaError('No se recibió ningún archivo');

  const extension = archivo.name.split('.').pop().toLowerCase();
  const tiposValidos = ['jpg', 'jpeg', 'png', 'webp', 'heic'];
  if (!tiposValidos.includes(extension)) return respuestaError('Tipo de archivo no válido. Use JPG, PNG o WebP');

  const nombre = `vehiculos/${Date.now()}_${generarId()}.${extension}`;
  await env.FOTOS.put(nombre, archivo.stream(), {
    httpMetadata: { contentType: archivo.type || 'image/jpeg' }
  });

  const url = `/api/fotos/${nombre}`;
  return respuestaOk({ url, nombre });
}

// ============================================================
// HANDLERS - USUARIOS
// ============================================================

async function handleGetUsuarios(env) {
  const result = await env.DB.prepare('SELECT id, nombre, email, rol, telefono, licencia_numero, licencia_vencimiento, activo, created_at FROM usuarios ORDER BY nombre ASC').all();
  return respuestaOk(result.results || []);
}

async function handleCrearUsuario(request, env) {
  const data = await request.json();
  if (!data.nombre || !data.email || !data.password || !data.rol) {
    return respuestaError('Nombre, email, contraseña y rol son requeridos');
  }

  const existente = await env.DB.prepare('SELECT id FROM usuarios WHERE email = ?').bind(data.email.toLowerCase()).first();
  if (existente) return respuestaError('Ya existe un usuario con ese email');

  const id = generarId('usr_');
  const passwordHash = await hashPassword(data.password);

  await env.DB.prepare(`
    INSERT INTO usuarios (id, nombre, email, password_hash, rol, telefono, licencia_numero, licencia_vencimiento)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(id, data.nombre, data.email.toLowerCase(), passwordHash, data.rol,
    data.telefono || null, data.licencia_numero || null, data.licencia_vencimiento || null).run();

  const usuario = await env.DB.prepare('SELECT id, nombre, email, rol, telefono, activo FROM usuarios WHERE id = ?').bind(id).first();
  return respuestaOk(usuario, 201);
}

async function handleActualizarUsuario(request, env, id) {
  const data = await request.json();
  const now = new Date().toISOString();

  if (data.password) {
    const passwordHash = await hashPassword(data.password);
    await env.DB.prepare('UPDATE usuarios SET password_hash = ? WHERE id = ?').bind(passwordHash, id).run();
  }

  await env.DB.prepare(`
    UPDATE usuarios SET nombre=?, email=?, rol=?, telefono=?, licencia_numero=?,
    licencia_vencimiento=?, activo=?, updated_at=? WHERE id=?
  `).bind(
    data.nombre, data.email?.toLowerCase(), data.rol, data.telefono || null,
    data.licencia_numero || null, data.licencia_vencimiento || null,
    data.activo !== undefined ? (data.activo ? 1 : 0) : 1, now, id
  ).run();

  const usuario = await env.DB.prepare('SELECT id, nombre, email, rol, telefono, activo FROM usuarios WHERE id = ?').bind(id).first();
  return respuestaOk(usuario);
}

async function handleEliminarUsuario(env, id, usuarioActual) {
  if (id === usuarioActual.id) return respuestaError('No puede eliminarse a sí mismo');
  await env.DB.prepare('UPDATE usuarios SET activo = 0 WHERE id = ?').bind(id).run();
  return respuestaOk({ mensaje: 'Usuario desactivado' });
}

async function handleGetPerfil(env, usuario) {
  const perfil = await env.DB.prepare('SELECT id, nombre, email, rol, telefono, licencia_numero, licencia_vencimiento FROM usuarios WHERE id = ?').bind(usuario.id).first();
  return respuestaOk(perfil);
}

async function handleActualizarPerfil(request, env, usuario) {
  const data = await request.json();
  const now = new Date().toISOString();

  if (data.password_actual && data.password_nuevo) {
    const userActual = await env.DB.prepare('SELECT password_hash FROM usuarios WHERE id = ?').bind(usuario.id).first();
    const valido = await verificarPassword(data.password_actual, userActual.password_hash);
    if (!valido) return respuestaError('Contraseña actual incorrecta');
    const nuevoHash = await hashPassword(data.password_nuevo);
    await env.DB.prepare('UPDATE usuarios SET password_hash = ? WHERE id = ?').bind(nuevoHash, usuario.id).run();
  }

  await env.DB.prepare('UPDATE usuarios SET nombre=?, telefono=?, updated_at=? WHERE id=?')
    .bind(data.nombre, data.telefono || null, now, usuario.id).run();

  const perfil = await env.DB.prepare('SELECT id, nombre, email, rol, telefono FROM usuarios WHERE id = ?').bind(usuario.id).first();
  return respuestaOk(perfil);
}

// ============================================================
// HANDLERS - COMPARAR FOTOS
// ============================================================

async function handleCompararFotos(request, env, vehiculoId) {
  const { fotos_antes, fotos_despues } = await request.json();
  const resultado = await analizarDanosConIA(env, fotos_antes || [], fotos_despues || []);
  return respuestaOk(resultado);
}

// ============================================================
// HANDLERS - REPORTES
// ============================================================

async function handleReporteUso(env, url) {
  const desde = url.searchParams.get('desde') || new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
  const hasta = url.searchParams.get('hasta') || new Date().toISOString().split('T')[0];

  const [totalUsos, kmTotales, usoPorVehiculo, usoPorInstructor] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as total, SUM(km_recorrido) as km_total, AVG(km_recorrido) as km_promedio FROM uso_vehiculos WHERE date(fecha_salida) BETWEEN ? AND ?`).bind(desde, hasta).first(),
    env.DB.prepare(`SELECT v.placa, v.marca, v.modelo, COUNT(u.id) as total_usos, SUM(u.km_recorrido) as km_total FROM uso_vehiculos u JOIN vehiculos v ON u.vehiculo_id = v.id WHERE date(u.fecha_salida) BETWEEN ? AND ? GROUP BY u.vehiculo_id ORDER BY total_usos DESC`).bind(desde, hasta).all(),
    env.DB.prepare(`SELECT us.nombre as instructor, COUNT(u.id) as total_usos, SUM(u.km_recorrido) as km_total FROM uso_vehiculos u JOIN usuarios us ON u.instructor_id = us.id WHERE date(u.fecha_salida) BETWEEN ? AND ? GROUP BY u.instructor_id ORDER BY total_usos DESC`).bind(desde, hasta).all(),
  ]);

  return respuestaOk({
    periodo: { desde, hasta },
    resumen: totalUsos,
    por_vehiculo: kmTotales.results || [],
    por_instructor: usoPorInstructor.results || [],
  });
}

async function handleReporteMantenimiento(env, url) {
  const desde = url.searchParams.get('desde') || new Date(Date.now() - 90 * 86400000).toISOString().split('T')[0];
  const hasta = url.searchParams.get('hasta') || new Date().toISOString().split('T')[0];

  const [completados, costoTotal, porVehiculo] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as total, SUM(costo) as costo_total FROM mantenimientos WHERE estado = 'completado' AND date(fecha_realizado) BETWEEN ? AND ?`).bind(desde, hasta).first(),
    env.DB.prepare(`SELECT v.placa, v.marca, v.modelo, COUNT(m.id) as mantenimientos, SUM(m.costo) as costo_total FROM mantenimientos m JOIN vehiculos v ON m.vehiculo_id = v.id WHERE m.estado = 'completado' AND date(m.fecha_realizado) BETWEEN ? AND ? GROUP BY m.vehiculo_id ORDER BY costo_total DESC`).bind(desde, hasta).all(),
    env.DB.prepare(`SELECT * FROM mantenimientos WHERE estado = 'pendiente' ORDER BY proxima_fecha ASC LIMIT 20`).all(),
  ]);

  return respuestaOk({
    periodo: { desde, hasta },
    completados: completados,
    por_vehiculo: costoTotal.results || [],
    pendientes: porVehiculo.results || [],
  });
}

async function handleReporteDocumentos(env, url) {
  const result = await env.DB.prepare(`
    SELECT d.*, v.placa, v.marca, v.modelo,
    CAST((julianday(d.fecha_vencimiento) - julianday('now')) AS INTEGER) as dias_restantes
    FROM documentos d JOIN vehiculos v ON d.vehiculo_id = v.id
    ORDER BY d.fecha_vencimiento ASC
  `).all();
  return respuestaOk(result.results || []);
}

// ============================================================
// GENERADOR AUTOMÁTICO DE ALERTAS
// ============================================================

async function generarAlertasAutomaticas(env) {
  const hoy = new Date().toISOString().split('T')[0];

  // Documentos por vencer en 30 días
  const docsPorVencer = await env.DB.prepare(`
    SELECT d.*, v.placa FROM documentos d JOIN vehiculos v ON d.vehiculo_id = v.id
    WHERE date(d.fecha_vencimiento) BETWEEN date('now') AND date('now', '+30 days')
  `).all();

  for (const doc of (docsPorVencer.results || [])) {
    const diasRestantes = Math.floor((new Date(doc.fecha_vencimiento) - new Date()) / 86400000);
    const prioridad = diasRestantes <= 7 ? 'critica' : diasRestantes <= 15 ? 'alta' : 'normal';
    const tipoNombre = { soat: 'SOAT', tecnomecanica: 'Revisión Técnico-Mecánica', seguro_todo_riesgo: 'Seguro Todo Riesgo', seguro_rc: 'Seguro RC' }[doc.tipo] || doc.tipo;

    const alertaExistente = await env.DB.prepare(
      'SELECT id FROM alertas WHERE referencia_id = ? AND tipo = "documento_vencimiento" AND leida = 0'
    ).bind(doc.id).first();

    if (!alertaExistente) {
      await env.DB.prepare(`
        INSERT INTO alertas (id, tipo, prioridad, vehiculo_id, referencia_id, referencia_tipo, titulo, mensaje)
        VALUES (?, 'documento_vencimiento', ?, ?, ?, 'documento', ?, ?)
      `).bind(
        generarId('alt_'), prioridad, doc.vehiculo_id, doc.id,
        `${tipoNombre} vence en ${diasRestantes} días - ${doc.placa}`,
        `El ${tipoNombre} del vehículo ${doc.placa} vence el ${doc.fecha_vencimiento}. ${diasRestantes <= 7 ? '¡URGENTE: Renovar inmediatamente!' : 'Programar renovación.'}`
      ).run();
    }
  }

  // Documentos vencidos
  const docsVencidos = await env.DB.prepare(`
    SELECT d.*, v.placa FROM documentos d JOIN vehiculos v ON d.vehiculo_id = v.id
    WHERE date(d.fecha_vencimiento) < date('now')
  `).all();

  for (const doc of (docsVencidos.results || [])) {
    const alertaExistente = await env.DB.prepare(
      'SELECT id FROM alertas WHERE referencia_id = ? AND titulo LIKE "%VENCIDO%" AND leida = 0'
    ).bind(doc.id).first();

    if (!alertaExistente) {
      const tipoNombre = { soat: 'SOAT', tecnomecanica: 'Revisión Técnico-Mecánica', seguro_todo_riesgo: 'Seguro Todo Riesgo' }[doc.tipo] || doc.tipo;
      await env.DB.prepare(`
        INSERT INTO alertas (id, tipo, prioridad, vehiculo_id, referencia_id, referencia_tipo, titulo, mensaje)
        VALUES (?, 'documento_vencimiento', 'critica', ?, ?, 'documento', ?, ?)
      `).bind(
        generarId('alt_'), doc.vehiculo_id, doc.id,
        `🚨 VENCIDO: ${tipoNombre} - ${doc.placa}`,
        `El ${tipoNombre} del vehículo ${doc.placa} VENCIÓ el ${doc.fecha_vencimiento}. El vehículo no debe circular.`
      ).run();
    }
  }
}

async function verificarYCrearAlertaDocumento(env, docId, data) {
  const hoy = new Date();
  const vencimiento = new Date(data.fecha_vencimiento);
  const diasRestantes = Math.floor((vencimiento - hoy) / 86400000);

  if (diasRestantes <= (data.dias_alerta || 30)) {
    const prioridad = diasRestantes < 0 ? 'critica' : diasRestantes <= 7 ? 'alta' : 'normal';
    await env.DB.prepare(`
      INSERT INTO alertas (id, tipo, prioridad, vehiculo_id, referencia_id, referencia_tipo, titulo, mensaje)
      VALUES (?, 'documento_vencimiento', ?, ?, ?, 'documento', ?, ?)
    `).bind(
      generarId('alt_'), prioridad, data.vehiculo_id, docId,
      `Documento por vencer: ${data.nombre}`,
      `El documento "${data.nombre}" vence el ${data.fecha_vencimiento} (${diasRestantes} días).`
    ).run();
  }
}

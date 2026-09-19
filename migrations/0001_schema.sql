-- ============================================================
-- ESCUELA AMERICANA DE CONDUCCIÓN
-- Sistema de Control de Vehículos
-- Schema Base de Datos - Cloudflare D1
-- ============================================================

-- Tabla de Usuarios (roles: director, administrador, instructor)
CREATE TABLE IF NOT EXISTS usuarios (
  id TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  rol TEXT NOT NULL CHECK (rol IN ('director', 'administrador', 'instructor')),
  telefono TEXT,
  licencia_numero TEXT,
  licencia_vencimiento TEXT,
  activo INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Tabla de Vehículos
CREATE TABLE IF NOT EXISTS vehiculos (
  id TEXT PRIMARY KEY,
  placa TEXT UNIQUE NOT NULL,
  marca TEXT NOT NULL,
  modelo TEXT NOT NULL,
  anio INTEGER NOT NULL,
  color TEXT,
  tipo TEXT NOT NULL CHECK (tipo IN ('automovil', 'moto', 'camion', 'bus', 'otro')),
  cilindraje INTEGER,
  num_motor TEXT,
  num_chasis TEXT,
  num_puertas INTEGER DEFAULT 4,
  transmision TEXT DEFAULT 'manual' CHECK (transmision IN ('manual', 'automatica')),
  combustible TEXT DEFAULT 'gasolina' CHECK (combustible IN ('gasolina', 'diesel', 'electrico', 'hibrido', 'gas')),
  kilometraje_actual INTEGER DEFAULT 0,
  estado TEXT DEFAULT 'activo' CHECK (estado IN ('activo', 'en_mantenimiento', 'inactivo', 'baja')),
  foto_principal TEXT,
  notas TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Tabla de Documentos de Vehículos (SOAT, Tecnomecánica, Seguros)
CREATE TABLE IF NOT EXISTS documentos (
  id TEXT PRIMARY KEY,
  vehiculo_id TEXT NOT NULL REFERENCES vehiculos(id) ON DELETE CASCADE,
  tipo TEXT NOT NULL CHECK (tipo IN ('soat', 'tecnomecanica', 'seguro_todo_riesgo', 'seguro_rc', 'tarjeta_propiedad', 'licencia_transito', 'revision_gases', 'otro')),
  nombre TEXT NOT NULL,
  numero_poliza TEXT,
  entidad TEXT,
  fecha_expedicion TEXT,
  fecha_vencimiento TEXT NOT NULL,
  valor_pago REAL,
  archivo_url TEXT,
  dias_alerta INTEGER DEFAULT 30,
  renovado INTEGER DEFAULT 0,
  notas TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Catálogo de Tipos de Mantenimiento
CREATE TABLE IF NOT EXISTS catalogo_mantenimiento (
  id TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  descripcion TEXT,
  categoria TEXT DEFAULT 'preventivo' CHECK (categoria IN ('preventivo', 'correctivo', 'predictivo')),
  aplica_a TEXT DEFAULT 'todos',
  intervalo_km INTEGER,
  intervalo_dias INTEGER,
  es_obligatorio INTEGER DEFAULT 0,
  orden INTEGER DEFAULT 0
);

-- Tabla de Registros de Mantenimiento
CREATE TABLE IF NOT EXISTS mantenimientos (
  id TEXT PRIMARY KEY,
  vehiculo_id TEXT NOT NULL REFERENCES vehiculos(id) ON DELETE CASCADE,
  catalogo_id TEXT REFERENCES catalogo_mantenimiento(id),
  nombre TEXT NOT NULL,
  descripcion TEXT,
  fecha_realizado TEXT,
  kilometraje_realizado INTEGER,
  proximo_km INTEGER,
  proxima_fecha TEXT,
  costo REAL,
  taller TEXT,
  mecanico TEXT,
  repuestos TEXT,
  factura_numero TEXT,
  archivo_url TEXT,
  estado TEXT DEFAULT 'pendiente' CHECK (estado IN ('pendiente', 'completado', 'cancelado')),
  realizado_por TEXT REFERENCES usuarios(id),
  notas TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Tabla de Control de Uso de Vehículos (Parqueadero)
CREATE TABLE IF NOT EXISTS uso_vehiculos (
  id TEXT PRIMARY KEY,
  vehiculo_id TEXT NOT NULL REFERENCES vehiculos(id),
  instructor_id TEXT NOT NULL REFERENCES usuarios(id),
  -- Datos de SALIDA
  fecha_salida TEXT NOT NULL,
  hora_salida TEXT NOT NULL,
  km_salida INTEGER NOT NULL,
  fotos_salida TEXT DEFAULT '[]',          -- JSON array de URLs en R2
  observaciones_salida TEXT,
  firma_salida TEXT,                         -- URL firma digital
  -- Datos de LLEGADA
  fecha_llegada TEXT,
  hora_llegada TEXT,
  km_llegada INTEGER,
  fotos_llegada TEXT DEFAULT '[]',          -- JSON array de URLs en R2
  observaciones_llegada TEXT,
  firma_llegada TEXT,
  -- Resumen
  km_recorrido INTEGER,
  duracion_minutos INTEGER,
  estado TEXT DEFAULT 'en_uso' CHECK (estado IN ('en_uso', 'devuelto')),
  -- Análisis de daños (IA)
  danos_detectados INTEGER DEFAULT 0,
  reporte_danos TEXT,                        -- JSON con descripción de daños detectados
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Tabla de Alertas del Sistema
CREATE TABLE IF NOT EXISTS alertas (
  id TEXT PRIMARY KEY,
  tipo TEXT NOT NULL CHECK (tipo IN ('documento_vencimiento', 'mantenimiento_vencido', 'mantenimiento_proximo', 'dano_detectado', 'vehiculo_inactivo', 'kilometraje', 'otro')),
  prioridad TEXT DEFAULT 'normal' CHECK (prioridad IN ('baja', 'normal', 'alta', 'critica')),
  vehiculo_id TEXT REFERENCES vehiculos(id),
  referencia_id TEXT,
  referencia_tipo TEXT,
  titulo TEXT NOT NULL,
  mensaje TEXT NOT NULL,
  leida INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- ============================================================
-- ÍNDICES para rendimiento
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_documentos_vehiculo ON documentos(vehiculo_id);
CREATE INDEX IF NOT EXISTS idx_documentos_vencimiento ON documentos(fecha_vencimiento);
CREATE INDEX IF NOT EXISTS idx_mantenimientos_vehiculo ON mantenimientos(vehiculo_id);
CREATE INDEX IF NOT EXISTS idx_mantenimientos_estado ON mantenimientos(estado);
CREATE INDEX IF NOT EXISTS idx_uso_vehiculo ON uso_vehiculos(vehiculo_id);
CREATE INDEX IF NOT EXISTS idx_uso_instructor ON uso_vehiculos(instructor_id);
CREATE INDEX IF NOT EXISTS idx_uso_estado ON uso_vehiculos(estado);
CREATE INDEX IF NOT EXISTS idx_alertas_leida ON alertas(leida);
CREATE INDEX IF NOT EXISTS idx_alertas_vehiculo ON alertas(vehiculo_id);

-- ============================================================
-- DATOS INICIALES - Catálogo de Mantenimientos
-- ============================================================
INSERT OR IGNORE INTO catalogo_mantenimiento (id, nombre, descripcion, categoria, aplica_a, intervalo_km, intervalo_dias, es_obligatorio, orden) VALUES
  ('cm001', 'Cambio de aceite de motor', 'Aceite y filtro de aceite', 'preventivo', 'todos', 5000, 90, 1, 1),
  ('cm002', 'Cambio de filtro de aire', 'Filtro de aire del motor', 'preventivo', 'todos', 15000, 180, 1, 2),
  ('cm003', 'Cambio de filtro de combustible', 'Filtro de gasolina/diesel', 'preventivo', 'todos', 20000, 180, 1, 3),
  ('cm004', 'Revisión y cambio de frenos', 'Pastillas, discos y líquido de frenos', 'preventivo', 'todos', 20000, 365, 1, 4),
  ('cm005', 'Revisión de llantas', 'Presión, desgaste y rotación', 'preventivo', 'todos', 10000, 90, 1, 5),
  ('cm006', 'Cambio de llantas', 'Reemplazo por desgaste excesivo', 'correctivo', 'todos', 40000, NULL, 0, 6),
  ('cm007', 'Revisión de batería', 'Carga y estado de batería', 'preventivo', 'todos', NULL, 180, 1, 7),
  ('cm008', 'Cambio de batería', 'Reemplazo de batería', 'correctivo', 'todos', NULL, 730, 0, 8),
  ('cm009', 'Revisión de correa de distribución', 'Correa o cadena de distribución', 'preventivo', 'automovil', 60000, NULL, 1, 9),
  ('cm010', 'Cambio de correa de distribución', 'Reemplazo preventivo', 'preventivo', 'automovil', 80000, NULL, 1, 10),
  ('cm011', 'Revisión de sistema eléctrico', 'Luces, señales y accesorios eléctricos', 'preventivo', 'todos', NULL, 180, 1, 11),
  ('cm012', 'Cambio de bujías', 'Bujías de encendido', 'preventivo', 'automovil', 20000, 365, 1, 12),
  ('cm013', 'Revisión de suspensión', 'Amortiguadores y sistema de suspensión', 'preventivo', 'todos', 20000, 365, 1, 13),
  ('cm014', 'Revisión de dirección', 'Sistema de dirección y alineación', 'preventivo', 'automovil', 10000, 180, 1, 14),
  ('cm015', 'Alineación y balanceo', 'Alineación de dirección y balanceo de llantas', 'preventivo', 'automovil', 10000, 180, 1, 15),
  ('cm016', 'Cambio de líquido de frenos', 'Líquido DOT hidráulico', 'preventivo', 'todos', NULL, 365, 1, 16),
  ('cm017', 'Revisión de sistema de enfriamiento', 'Radiador, mangueras y anticongelante', 'preventivo', 'todos', 20000, 365, 1, 17),
  ('cm018', 'Cambio de anticongelante', 'Líquido refrigerante del motor', 'preventivo', 'todos', NULL, 730, 1, 18),
  ('cm019', 'Revisión de transmisión', 'Caja de cambios y embrague', 'preventivo', 'todos', 30000, 365, 1, 19),
  ('cm020', 'Limpieza de inyectores', 'Limpieza del sistema de inyección', 'preventivo', 'automovil', 30000, 365, 0, 20),
  ('cm021', 'Revisión de cadena (moto)', 'Cadena y piñones de transmisión', 'preventivo', 'moto', 3000, 60, 1, 21),
  ('cm022', 'Lubricación de cadena (moto)', 'Lubricante de cadena', 'preventivo', 'moto', 1000, 30, 1, 22),
  ('cm023', 'Revisión de carburador (moto)', 'Carburador o sistema de inyección', 'preventivo', 'moto', 10000, 180, 1, 23),
  ('cm024', 'Revisión de freno de mano', 'Cable y mecanismo de freno de mano', 'preventivo', 'automovil', NULL, 365, 1, 24),
  ('cm025', 'Diagnóstico electrónico', 'Escáner diagnóstico del sistema OBD', 'preventivo', 'todos', NULL, 365, 0, 25);

-- ============================================================
-- USUARIO ADMINISTRADOR INICIAL
-- Password: Admin2024! (bcrypt hash)
-- IMPORTANTE: Cambiar la contraseña después del primer login
-- ============================================================
INSERT OR IGNORE INTO usuarios (id, nombre, email, password_hash, rol) VALUES
  ('usr_admin', 'Administrador del Sistema', 'admin@escuela.com',
   '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
   'director');

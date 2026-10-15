# 🚗 Sistema de Control de Vehículos
## Escuela Americana de Conducción

Plataforma web completa para la gestión de flota vehicular de escuelas de conducción. Desarrollada sobre **Cloudflare Pages + Workers + D1 + R2**.

---

## ✅ Módulos incluidos

| Módulo | Descripción |
|--------|------------|
| **Dashboard** | Resumen ejecutivo, alertas activas, vehículos en uso en tiempo real |
| **Flota Vehicular** | Hoja de vida completa de cada vehículo (placa, tipo, KM, estado) |
| **Documentos y Seguros** | SOAT, Tecnomecánica, seguros — con alertas automáticas de vencimiento |
| **Mantenimiento** | 25+ tipos de mantenimiento preventivo, programación, historial y costos |
| **Control de Uso** | Registro de salida/llegada con fotos y análisis de daños por IA |
| **Reportes** | Uso por vehículo e instructor, costos de mantenimiento, estado documental |
| **Usuarios** | Roles: Director, Administrador, Instructor |

---

## 🚀 Despliegue paso a paso

### Paso 1 — Prerrequisitos

1. Crear cuenta en [Cloudflare](https://dash.cloudflare.com/sign-up) (gratis)
2. Crear cuenta en [GitHub](https://github.com) (gratis)
3. Instalar Node.js desde [nodejs.org](https://nodejs.org)
4. Instalar Wrangler (herramienta de Cloudflare):
   ```bash
   npm install -g wrangler
   wrangler login
   ```

### Paso 2 — Crear repositorio en GitHub

1. Ir a GitHub → **New repository**
2. Nombre: `escuela-conduccion-vehiculos`
3. Privado o público (recomendamos privado)
4. Copiar todos los archivos de este proyecto al repositorio:
   ```bash
   git init
   git add .
   git commit -m "Sistema de control de vehículos - versión inicial"
   git remote add origin https://github.com/TU_USUARIO/escuela-conduccion-vehiculos.git
   git push -u origin main
   ```

### Paso 3 — Crear la Base de Datos D1

```bash
# Crear la base de datos
wrangler d1 create escuela_conduccion_db

# El comando anterior imprime algo así:
# ✅  Successfully created DB 'escuela_conduccion_db' (ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

# COPIAR ese ID y pegarlo en wrangler.toml donde dice "REEMPLAZAR_CON_ID_DE_D1"
```

### Paso 4 — Aplicar el Schema a la base de datos

```bash
# Aplicar en producción
wrangler d1 migrations apply escuela_conduccion_db

# Para pruebas locales
wrangler d1 migrations apply escuela_conduccion_db --local
```

### Paso 5 — Configurar wrangler.toml

El `wrangler.toml` ya tiene el ID de D1 configurado (`aeacf8ed-04bd-40f1-853e-c40fc7836e54`).
Solo generar la clave secreta JWT en https://generate-secret.vercel.app/32 y actualizarla en el archivo.

### Paso 6 — Conectar GitHub con Cloudflare Pages

1. Ir a [Cloudflare Dashboard](https://dash.cloudflare.com) → **Pages**
2. Clic en **Create a project** → **Connect to Git**
3. Seleccionar el repositorio de GitHub
4. Configuración de Build:
   - **Build command**: (vacío — no necesita compilación)
   - **Build output directory**: `public`
5. Clic en **Save and Deploy**

### Paso 8 — Configurar Variables de Entorno en Pages

En Cloudflare Pages → Settings → Environment variables, agregar:
```
JWT_SECRET = (la clave generada en el paso 6)
DIAS_ALERTA_DOCUMENTOS = 30
DIAS_ALERTA_MANTENIMIENTO = 15
```

### Paso 9 — Vincular D1 y AI a Pages Functions

En Cloudflare Pages → Settings → Functions:
- **D1 database bindings**: Nombre `DB` → Base de datos `escuela_conduccion_db`
- **AI binding**: Nombre `AI` (habilitar Workers AI — gratuito hasta 10,000 req/día)

> 📦 **R2 (fotos)**: Desactivado en fase gratuita. Las fotos se almacenan directamente en D1 como base64.
> Cuando el proyecto sea aprobado, activar R2 desde el Dashboard y descomentar el binding en `wrangler.toml`.

---

## 🔐 Primer acceso al sistema

Una vez desplegado, acceder a la URL de Cloudflare Pages (ej: `https://escuela-conduccion.pages.dev`):

| Campo | Valor |
|-------|-------|
| **Email** | admin@escuela.com |
| **Contraseña** | Admin2024! |

> ⚠️ **Importante**: Cambiar la contraseña inmediatamente después del primer login en el módulo de Usuarios.

---

## 👥 Roles de Usuario

| Rol | Permisos |
|-----|----------|
| **Director** | Acceso total: vehículos, documentos, mantenimiento, uso, reportes, usuarios |
| **Administrador** | Todo excepto gestión de usuarios y eliminación de vehículos |
| **Instructor** | Solo puede registrar salida/llegada de sus propios vehículos asignados |

---

## 🔔 Sistema de Alertas Automáticas

El sistema genera alertas automáticas en cada login:

- 🔴 **Crítica**: Documentos vencidos / Documentos que vencen en ≤7 días
- 🟠 **Alta**: Documentos que vencen en 8-15 días
- 🟡 **Normal**: Documentos que vencen en 16-30 días

---

## 🔧 Mantenimientos incluidos en el catálogo

El sistema incluye **25 tipos de mantenimiento** preconfigurados, entre ellos:

- Cambio de aceite y filtro (cada 5,000 km / 3 meses)
- Cambio de filtros (aire, combustible)
- Revisión y cambio de frenos
- Revisión de llantas, batería, suspensión
- Cambio de correa de distribución
- Revisión eléctrica, bujías, dirección
- Alineación y balanceo
- Mantenimientos específicos de motos (cadena, carburador)
- Revisión del sistema de enfriamiento
- Diagnóstico electrónico OBD

---

## 📷 Sistema de Fotos y Análisis IA

Al registrar **llegada de un vehículo**:
1. El instructor toma fotos del vehículo
2. La IA de Cloudflare (Workers AI) compara las fotos de salida vs llegada
3. Si detecta diferencias (golpes, rayones), genera una alerta automática al director
4. Todas las fotos quedan almacenadas en R2 (permanentes)

---

## 🏗 Estructura del Proyecto

```
escuela-conduccion/
├── public/
│   └── index.html          # Frontend SPA completo
├── functions/
│   └── api/
│       └── [[route]].js    # API Backend (Cloudflare Pages Functions)
├── migrations/
│   └── 0001_schema.sql     # Schema de base de datos D1
├── wrangler.toml           # Configuración Cloudflare
├── package.json
└── README.md
```

---

## 🔄 Flujo de uso típico

```
1. Instructor llega → abre el sistema en el celular
2. Va a "Control de Uso" → "Registrar Salida"
3. Selecciona el vehículo y anota el KM del odómetro
4. Toma fotos del vehículo (4 ángulos mínimo)
5. Sale a dar la clase

6. Al terminar → "Registrar Llegada"
7. Anota KM de llegada
8. Toma fotos del vehículo al regresar
9. La IA compara y detecta si hay daños nuevos
10. El director recibe alerta inmediata si hay novedad
```

---

## 💡 Desarrollo local (para pruebas)

```bash
npm install
npm run db:migrate:local
npm run dev
# Abrir: http://localhost:8788
```

---

*Sistema desarrollado para Escuela Americana de Conducción.*
*Tecnología: Cloudflare Pages · Workers · D1 · R2 · Workers AI*

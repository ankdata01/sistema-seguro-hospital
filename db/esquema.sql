PRAGMA foreign_keys = ON;

CREATE TABLE personal (
    id TEXT PRIMARY KEY,
    nombre TEXT NOT NULL,
    rol TEXT NOT NULL,
    especialidad TEXT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    mfa_secret TEXT NOT NULL,
    llave_publica TEXT NOT NULL,
    activo INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE pacientes (
    id TEXT PRIMARY KEY,
    nombre TEXT NOT NULL,
    fecha_nacimiento TEXT NOT NULL,
    contacto TEXT
);

CREATE TABLE citas (
    id TEXT PRIMARY KEY,
    paciente_id TEXT NOT NULL REFERENCES pacientes(id),
    personal_id TEXT NOT NULL REFERENCES personal(id),
    fecha TEXT NOT NULL,
    estado TEXT NOT NULL,
    es_emergencia INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE historial_clinico (
    id TEXT PRIMARY KEY,
    paciente_id TEXT NOT NULL REFERENCES pacientes(id),
    personal_id TEXT NOT NULL REFERENCES personal(id),
    diagnostico TEXT NOT NULL,
    tratamiento TEXT NOT NULL,
    fecha TEXT NOT NULL,
    hash_registro TEXT NOT NULL,
    firma_digital TEXT NOT NULL
);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    personal_id TEXT REFERENCES personal(id),
    entidad_afectada TEXT NOT NULL,
    entidad_id TEXT,
    accion TEXT NOT NULL,
    detalle TEXT,
    ip_origen TEXT,
    fecha_hora TEXT NOT NULL,
    hash_anterior TEXT NOT NULL,
    hash_actual TEXT NOT NULL
);

CREATE INDEX idx_historial_paciente ON historial_clinico(paciente_id);
CREATE INDEX idx_audit_fecha ON audit_log(fecha_hora);

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log es inmutable: UPDATE no permitido');
END;

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log es inmutable: DELETE no permitido');
END;

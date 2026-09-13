"""Decorator de auditoría sobre ServicioClinico."""
from datetime import datetime, timezone
from app.clinico.modelos import Paciente, NotaClinica
from app.clinico.servicio_clinico import ServicioClinico
from app.datos.repo_auditoria import RepoAuditoria

class AuditoriaDecorator:
    def __init__(self, servicio: ServicioClinico, repo_auditoria: RepoAuditoria) -> None:
        self._svc = servicio; self._audit = repo_auditoria
    def listar_pacientes(self) -> list[Paciente]: return self._svc.listar_pacientes()
    def obtener_historial(self, paciente_id: str, personal_id: str, ip: str) -> tuple[Paciente, list[NotaClinica]]:
        resultado = self._svc.obtener_historial(paciente_id); self._auditar(personal_id, "historial_clinico", paciente_id, "CONSULTAR_HISTORIAL", None, ip); return resultado
    def crear_nota(self, nota: NotaClinica, personal_id: str, ip: str) -> NotaClinica:
        resultado = self._svc.crear_nota(nota); self._auditar(personal_id, "historial_clinico", nota.id, "CREAR_NOTA", f"Paciente {nota.paciente_id[:8]}…", ip); return resultado
    def _auditar(self, personal_id: str, entidad_afectada: str, entidad_id: str | None, accion: str, detalle: str | None, ip: str) -> None:
        fecha_hora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._audit.insertar_encadenado(personal_id=personal_id, entidad_afectada=entidad_afectada, entidad_id=entidad_id, accion=accion, detalle=detalle, ip_origen=ip, fecha_hora=fecha_hora)

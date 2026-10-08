# -*- coding: utf-8 -*-
"""
services/esquemas.py
Modelos Pydantic de la salida de cada etapa LLM. Lo que no cumple el
esquema se rechaza aqui; las correcciones que no requieren rechazar la
respuesta (IPs desconocidas, falso_positivo sin evidencia) se aplican en
los validadores y quedan anotadas en `avisos`.
"""

import ipaddress
import logging
import re
from typing import Literal

from pydantic import BaseModel, Field, PrivateAttr, ValidationInfo, field_validator, model_validator

logger = logging.getLogger('AgenteSDN.esquemas')

# Mismo conjunto que resuelve services/pipeline.py::resolver_solicitud
CONSULTAS_VALIDAS = (
    'historial_host', 'flujos_switch', 'estado_puertos', 'hosts_bloqueados', 'hosts_riesgo',
)

Consulta  = Literal['historial_host', 'flujos_switch', 'estado_puertos', 'hosts_bloqueados', 'hosts_riesgo']
Veredicto = Literal['confirmado', 'falso_positivo', 'indeterminado', 'ya_contenido']
Severidad = Literal['baja', 'media', 'alta', 'critica']

MAX_MENSAJE_TELEGRAM = 600
MAX_RECOMENDACIONES  = 4


class _ConAvisos(BaseModel):
    _avisos: list[str] = PrivateAttr(default_factory=list)

    @property
    def avisos(self) -> list[str]:
        return self._avisos


# =============================================================================
# Etapa 1 -- Triage
# =============================================================================

class SalidaTriage(BaseModel):
    consultas: list[Consulta]
    razon: str = ''


# =============================================================================
# Etapa 2 -- Veredicto
# =============================================================================

class SalidaVeredicto(_ConAvisos):
    """
    Validar con contexto para filtrar hosts_en_riesgo:
        SalidaVeredicto.model_validate(datos, context={'ips_conocidas': {...},
                                                       'ip_origen': '10.0.10.3'})
    Sin contexto solo se descartan las IPs con formato invalido.
    """
    veredicto: Veredicto
    confianza: int = Field(ge=0, le=100)
    severidad: Severidad
    razonamiento: str
    evidencia_legitima: str | None = None
    hosts_en_riesgo: list[str] = Field(default_factory=list)

    @field_validator('evidencia_legitima', mode='before')
    @classmethod
    def _evidencia_vacia_es_null(cls, v):
        if isinstance(v, str) and v.strip().lower() in ('', 'null', 'none', 'ninguna', 'n/a'):
            return None
        return v

    @model_validator(mode='after')
    def _normalizar(self, info: ValidationInfo):
        ctx = info.context or {}
        conocidas = ctx.get('ips_conocidas')
        origen = ctx.get('ip_origen')

        validas = []
        for ip in self.hosts_en_riesgo:
            ip = str(ip).strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self._avisar(f'hosts_en_riesgo: IP invalida descartada "{ip}"')
                continue
            if conocidas is not None and ip not in conocidas:
                self._avisar(f'hosts_en_riesgo: {ip} no aparece en los datos enviados, descartada')
                continue
            if ip == origen:
                self._avisar(f'hosts_en_riesgo: {ip} es el host de origen, descartada')
                continue
            if ip not in validas:
                validas.append(ip)
        self.hosts_en_riesgo = validas

        # Nunca falso_positivo sin un dato concreto que lo respalde
        if self.veredicto == 'falso_positivo' and self.evidencia_legitima is None:
            self._avisar('falso_positivo sin evidencia_legitima: degradado a indeterminado')
            self.veredicto = 'indeterminado'
        return self

    def _avisar(self, texto: str) -> None:
        logger.warning(f'[Esquemas] {texto}')
        self._avisos.append(texto)


# =============================================================================
# Etapa 3 -- Respuesta
# =============================================================================

_ETIQUETAS_PERMITIDAS = ('<b>', '</b>', '<code>', '</code>')
_ENTIDAD = re.compile(r'&(?!(?:amp|lt|gt|quot|#\d+);)')


def escapar_html_telegram(texto: str) -> str:
    """
    Escapa < y > salvo en <b>, </b>, <code>, </code> (lo unico que se
    permite en el mensaje). Tambien escapa los & sueltos, que el parse_mode
    HTML de Telegram rechaza.
    """
    texto = _ENTIDAD.sub('&amp;', texto)
    partes = re.split(r'(</?(?:b|code)>)', texto)
    return ''.join(
        p if p in _ETIQUETAS_PERMITIDAS else p.replace('<', '&lt;').replace('>', '&gt;')
        for p in partes
    )


class SalidaRespuesta(BaseModel):
    mensaje_telegram: str = Field(min_length=1, max_length=MAX_MENSAJE_TELEGRAM)
    recomendaciones_forenses: list[str] = Field(max_length=MAX_RECOMENDACIONES)

    @field_validator('mensaje_telegram', mode='after')
    @classmethod
    def _escapar_mensaje(cls, v: str) -> str:
        return escapar_html_telegram(v.strip())

    @field_validator('recomendaciones_forenses', mode='after')
    @classmethod
    def _escapar_recomendaciones(cls, v: list[str]) -> list[str]:
        # Tambien se envian por Telegram con parse_mode HTML (agente.py)
        return [escapar_html_telegram(r.strip()) for r in v if r.strip()]

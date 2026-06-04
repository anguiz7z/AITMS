"""Diagram-to-System ingestion (Visio .vsdx and other supported formats)."""

from .vsdx import vsdx_to_system, vsdx_to_system_yaml

__all__ = ["vsdx_to_system_yaml", "vsdx_to_system"]

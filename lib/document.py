#!/usr/bin/env python3
##
# omnibus - deadbits.
# document model for artifacts
##
from lib.common import detect_type, timestamp

class Document:
    def __init__(self, name, type=None, source=None, subtype=None, parent=None, created=None, children=None, tags=None, notes=None, data=None):
        self.name = name
        self.type = type or detect_type(name)
        self.subtype = subtype
        self.source = source or 'user'
        self.parent = parent
        self.created = created or timestamp()
        self.children = children or []
        self.tags = tags or []
        self.notes = notes or []
        self.data = data or {}

    def __dict__(self):
        return {
            'name': self.name,
            'type': self.type,
            'subtype': self.subtype,
            'source': self.source,
            'parent': self.parent,
            'created': self.created,
            'children': self.children,
            'tags': self.tags,
            'notes': self.notes,
            'data': self.data
        }

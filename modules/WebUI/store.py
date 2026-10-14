from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path


class WebStore:
    def __init__(self, database: Path):
        database.parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, target TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, module TEXT NOT NULL,
                    profile TEXT NOT NULL, output_dir TEXT NOT NULL, status TEXT NOT NULL,
                    pid INTEGER, created_at REAL NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                );
            """)

    def _connect(self):
        db = sqlite3.connect(self.database)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def create_project(self, name: str, target: str) -> dict:
        project = {"id": uuid.uuid4().hex, "name": name, "target": target,
                   "created_at": time.time()}
        with self._connect() as db:
            db.execute("INSERT INTO projects VALUES (:id,:name,:target,:created_at)", project)
        return project

    def projects(self) -> list[dict]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM projects ORDER BY created_at DESC")]

    def project(self, project_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
            return dict(row) if row else None

    def create_scan(self, project_id: str, module: str, profile: str,
                    output_dir: str, pid: int | None,
                    status: str = "running") -> dict:
        if status not in {"running", "completed", "failed", "cancelled"}:
            raise ValueError(f"invalid scan status: {status}")
        scan = {"id": uuid.uuid4().hex, "project_id": project_id, "module": module,
                "profile": profile, "output_dir": output_dir, "status": status,
                "pid": pid, "created_at": time.time()}
        with self._connect() as db:
            db.execute("INSERT INTO scans VALUES (:id,:project_id,:module,:profile,:output_dir,"
                       ":status,:pid,:created_at)", scan)
        return scan

    def scans(self, project_id: str | None = None) -> list[dict]:
        with self._connect() as db:
            if project_id:
                rows = db.execute("SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC",
                                  (project_id,))
            else:
                rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC")
            return [dict(row) for row in rows]

    def scan(self, scan_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            return dict(row) if row else None

    def update_scan_status(self, scan_id: str, status: str) -> dict | None:
        if status not in {"running", "completed", "failed", "cancelled"}:
            raise ValueError(f"invalid scan status: {status}")
        with self._connect() as db:
            db.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
        return self.scan(scan_id)

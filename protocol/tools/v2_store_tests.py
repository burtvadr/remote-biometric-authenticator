#!/usr/bin/env python3
"""Independent SQLite tests for the checked-in host schema, not Rust API tests."""
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

SCHEMA = pathlib.Path(__file__).resolve().parents[2] / 'linux/rbad/src/v2_store/schema.sql'
NOW = 1000

def ident(n): return bytes([n]) * 16

def connect(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA journal_mode=DELETE')
    db.execute('PRAGMA synchronous=EXTRA')
    return db

def setup(path):
    db = connect(path)
    db.executescript(SCHEMA.read_text())
    db.execute('INSERT INTO host_meta VALUES (1,?,?)', (ident(99), NOW))
    db.execute('INSERT INTO principals VALUES (?,?,?,?,1)', (ident(1),1000,'alice',ident(51)))
    return db

def credential(db, n, owner=1):
    # Structurally shaped public-key bytes; cryptographic validation is Rust's job.
    k1, k2 = b'\x04' + bytes([n])*64, b'\x04' + bytes([n+1])*64
    db.execute('INSERT INTO credentials VALUES(?,?,1,?,?,?,?,?,?,?,?,?,NULL,NULL)', (ident(n),ident(owner),k1,k2,b'chain',b'chain',NOW,NOW+100000,NOW,NOW+86400,bytes([n])*32))
    db.execute('INSERT INTO key_history VALUES (?,?,0)', (k1,ident(n)))
    db.execute('INSERT INTO key_history VALUES (?,?,1)', (k2,ident(n)))
    db.execute('INSERT INTO enrollments VALUES (?,?,?,?,?)', (ident(n+20),ident(n),bytes([n+1])*32,bytes([n+2])*32,NOW))
    db.execute("INSERT INTO grants VALUES (?,?,?,'authenticate','rba','authenticate')", (ident(n),ident(owner),ident(owner)))

class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / 'test.sqlite3'
        self.db = setup(self.path)
    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
    def test_profile(self):
        self.assertEqual(self.db.execute('PRAGMA application_id').fetchone()[0], 0x52424132)
        self.assertEqual(self.db.execute('PRAGMA user_version').fetchone()[0], 2)
        self.assertEqual(self.db.execute('PRAGMA synchronous').fetchone()[0], 3)
        self.assertEqual(self.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
    def test_uid_reuse_requires_deactivation(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('INSERT INTO principals VALUES (?,?,?,?,1)',(ident(2),1000,'bob',ident(52)))
        self.db.execute('UPDATE principals SET active=0 WHERE id=?',(ident(1),))
        self.db.execute('INSERT INTO principals VALUES (?,?,?,?,1)',(ident(2),1000,'alice',ident(52)))
        self.assertEqual(self.db.execute('SELECT id FROM principals WHERE active=1').fetchone()[0],ident(2))
    def test_invalid_scope_and_approver_rejected(self):
        credential(self.db,10)
        self.db.execute('INSERT INTO principals VALUES (?,?,?,?,1)',(ident(2),1001,'bob',ident(52)))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO grants VALUES(?,?,?,'authenticate','*','authenticate')",(ident(10),ident(1),ident(1)))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO grants VALUES(?,?,?,'authenticate','rba','authenticate')",(ident(10),ident(2),ident(2)))
    def test_status_freshness_constraint(self):
        credential(self.db,10)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('UPDATE credentials SET status_until=?',(NOW+86401,))
        self.db.execute('UPDATE credentials SET status_checked_at=?,status_until=?',(NOW+50000,NOW+130000))
    def test_rollback_replacement(self):
        credential(self.db,10)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('UPDATE credentials SET revoked_at=?,retry_until=?,revision=2 WHERE id=?',(NOW,NOW+2592000,ident(10)))
            self.db.execute('DELETE FROM grants WHERE credential=?',(ident(10),))
            with self.assertRaises(sqlite3.IntegrityError):
                credential(self.db,11) # old biometric key reused as new transport key
        finally:
            self.db.rollback()
        self.assertEqual(self.db.execute('SELECT revoked_at,revision FROM credentials').fetchall(),[(None,1)])
        self.assertEqual(self.db.execute('SELECT count(*) FROM grants').fetchone()[0],1)
    def test_crash_rollback_and_committed_reopen(self):
        credential(self.db,10)
        self.db.close()
        code = '''import sqlite3,sys,os
c=sqlite3.connect(sys.argv[1],isolation_level=None)
c.execute('PRAGMA synchronous=EXTRA')
c.execute('BEGIN IMMEDIATE')
c.execute('UPDATE credentials SET revoked_at=1000,retry_until=2593000,revision=2')
c.execute('DELETE FROM grants')
if sys.argv[2]=='commit': c.commit()
os._exit(0)
'''
        subprocess.run([sys.executable,'-c',code,str(self.path),'crash'],check=True)
        self.db=connect(self.path)
        self.assertEqual(self.db.execute('SELECT revoked_at,revision FROM credentials').fetchall(),[(None,1)])
        self.assertEqual(self.db.execute('SELECT count(*) FROM grants').fetchone()[0],1)
        self.db.close()
        subprocess.run([sys.executable,'-c',code,str(self.path),'commit'],check=True)
        self.db=connect(self.path)
        self.assertEqual(self.db.execute('SELECT revoked_at,revision FROM credentials').fetchall(),[(NOW,2)])
        self.assertEqual(self.db.execute('SELECT count(*) FROM grants').fetchone()[0],0)
    def test_concurrent_transaction_reservation(self):
        # Independent reproduction of the transaction invariant, not the Rust method.
        def reserve(_):
            with connect(self.path) as db:
                db.execute('BEGIN IMMEDIATE')
                count=db.execute('SELECT count(*) FROM admission WHERE kind=1 AND subject=? AND at>?',(ident(0),NOW-60)).fetchone()[0]
                if count>=6:
                    db.commit();return False
                db.execute('INSERT INTO admission(kind,subject,at) VALUES(1,?,?)',(ident(0),NOW))
                db.commit();return True
        with ThreadPoolExecutor(max_workers=8) as pool:
            result=list(pool.map(reserve,range(24)))
        self.assertEqual(sum(result),6)
        self.assertEqual(self.db.execute('SELECT count(*) FROM admission').fetchone()[0],6)
    def test_audit_failure_rolls_back(self):
        credential(self.db,10)
        self.db.execute("CREATE TRIGGER fail BEFORE INSERT ON audit_outbox BEGIN SELECT RAISE(ABORT,'injected failure'); END")
        self.db.execute('BEGIN IMMEDIATE')
        self.db.execute('DELETE FROM grants')
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO audit_outbox(kind,subject,at) VALUES('revoke',?,?)",(ident(10),NOW))
        self.db.rollback()
        self.assertEqual(self.db.execute('SELECT count(*) FROM grants').fetchone()[0],1)

if __name__ == '__main__':
    print('SQLite',sqlite3.sqlite_version,flush=True)
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Independent SQLite checks using the actual Android schema constants.
These do not execute Android's SQLite binding or AndroidKeyStore.
"""
from pathlib import Path
import sqlite3
import tempfile
import unittest
SOURCE=Path(__file__).resolve().parents[2]/'android/app/src/main/kotlin/io/github/burtvadr/rba/session/V2DeviceStore.kt'
TEXT=SOURCE.read_text()
SCHEMA=TEXT.split('private const val SCHEMA="""',1)[1].split('"""',1)[0]
INDEX=TEXT.split('private const val INDEX="',1)[1].split('"',1)[0]
POLICY=TEXT.split('private const val POLICY_SCHEMA="""',1)[1].split('"""',1)[0]
REVOCATION=TEXT.split('private const val REVOCATION_SCHEMA="""',1)[1].split('"""',1)[0]
CLEANUP=TEXT.split('private const val CLEANUP_SCHEMA="""',1)[1].split('"""',1)[0]
ROW=('a'*32,'b'*32,'c'*32,0,b'pending',100,86500)
class StoreTests(unittest.TestCase):
    def setup(self, db):
        db.executescript('PRAGMA foreign_keys=ON;'+SCHEMA+';'+INDEX+';'+POLICY+';'+REVOCATION+';'+CLEANUP+';')
        db.execute('insert into enrollment_records values(?,?,?,?,?,?,?)',ROW);db.commit()
    def test_schema_roundtrip_and_bounds(self):
        with sqlite3.connect(':memory:') as db:
            self.setup(db)
            self.assertEqual(db.execute("select sql from sqlite_master where name='enrollment_records'").fetchone()[0],SCHEMA)
            self.assertEqual(db.execute("select sql from sqlite_master where name='pending_per_host'").fetchone()[0],INDEX)
            for row in [('d'*32,'e'*32,'f'*32,2,b'pending',100,86500),('d'*32,'e'*32,'f'*32,0,b'pending',100,86501),('d'*32,'e'*32,'f'*32,0,b'',100,86500)]:
                with self.assertRaises(sqlite3.IntegrityError): db.execute('insert into enrollment_records values(?,?,?,?,?,?,?)',row)
    def test_one_pending_per_host(self):
        with sqlite3.connect(':memory:') as db:
            self.setup(db)
            with self.assertRaises(sqlite3.IntegrityError): db.execute('insert into enrollment_records values(?,?,?,?,?,?,?)',('d'*32,'b'*32,'e'*32,0,b'other',100,86500))
            db.execute('update enrollment_records set state=1 where credential=? and state=0',(ROW[0],))
            db.execute('insert into enrollment_records values(?,?,?,?,?,?,?)',('d'*32,'b'*32,'e'*32,0,b'other',100,86500))
            self.assertEqual(db.execute('select count(*) from enrollment_records where state=1').fetchone()[0],1)
    def test_durable_pending_and_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'state.sqlite3')
            db=sqlite3.connect(path);self.setup(db);db.close()
            db=sqlite3.connect(path)
            self.assertEqual(db.execute('select record from enrollment_records where state=0').fetchone()[0],b'pending')
            db.execute('update enrollment_records set state=1 where credential=? and state=0',(ROW[0],));db.rollback();db.close()
            db=sqlite3.connect(path)
            self.assertEqual(db.execute('select state from enrollment_records').fetchone()[0],0)
            self.assertEqual(db.execute('update enrollment_records set state=1 where credential=? and state=0',(ROW[0],)).rowcount,1);db.commit();db.close()
            db=sqlite3.connect(path)
            self.assertEqual(db.execute('update enrollment_records set state=1 where credential=? and state=0',(ROW[0],)).rowcount,0);db.close()
    def test_policy_transaction_and_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'state.sqlite3')
            db=sqlite3.connect(path);self.setup(db)
            db.execute('update enrollment_records set state=1 where credential=?',(ROW[0],))
            db.execute('insert into policy_records values(?,?)',(ROW[0],b'revision1'));db.commit()
            db.execute('update policy_records set snapshot=? where credential=?',(b'revision2',ROW[0]));db.rollback();db.close()
            db=sqlite3.connect(path);db.execute('pragma foreign_keys=on')
            self.assertEqual(db.execute('select snapshot from policy_records').fetchone()[0],b'revision1')
            self.assertEqual(db.execute('update policy_records set snapshot=? where credential=? and snapshot=?',(b'revision2',ROW[0],b'revision1')).rowcount,1);db.commit()
            self.assertEqual(db.execute('update policy_records set snapshot=? where credential=? and snapshot=?',(b'stale',ROW[0],b'revision1')).rowcount,0)
            self.assertEqual(db.execute('select record from enrollment_records').fetchone()[0],b'pending')
            with self.assertRaises(sqlite3.IntegrityError):db.execute('insert into policy_records values(?,?)',('d'*32,b'orphan'))
            db.execute('delete from enrollment_records where credential=?',(ROW[0],));self.assertEqual(db.execute('select count(*) from policy_records').fetchone()[0],0);db.close()
    def test_revocation_denial_survives_restart_and_receipt_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'state.sqlite3')
            db=sqlite3.connect(path);self.setup(db)
            db.execute('update enrollment_records set state=1 where credential=?',(ROW[0],))
            db.execute('insert into policy_records values(?,?)',(ROW[0],b'policy'))
            db.execute('insert into revocation_records values(?,0)',(ROW[0],));db.commit();db.close()
            db=sqlite3.connect(path);db.execute('pragma foreign_keys=on')
            active='select count(*) from enrollment_records e where e.state=1 and not exists(select 1 from revocation_records r where r.credential=e.credential)'
            self.assertEqual(db.execute(active).fetchone()[0],0)
            self.assertEqual(db.execute('select acknowledged from revocation_records').fetchone()[0],0)
            db.execute('update revocation_records set acknowledged=1 where credential=? and acknowledged=0',(ROW[0],));db.rollback();db.close()
            db=sqlite3.connect(path);db.execute('pragma foreign_keys=on')
            self.assertEqual(db.execute(active).fetchone()[0],0)
            self.assertEqual(db.execute('update revocation_records set acknowledged=1 where credential=? and acknowledged=0',(ROW[0],)).rowcount,1);db.commit();db.close()
            db=sqlite3.connect(path);db.execute('pragma foreign_keys=on')
            self.assertEqual(db.execute(active).fetchone()[0],0)
            self.assertEqual(db.execute('select acknowledged from revocation_records').fetchone()[0],1)
            self.assertEqual(db.execute('update revocation_records set acknowledged=1 where credential=? and acknowledged=0',(ROW[0],)).rowcount,0)
            db.execute('delete from enrollment_records where credential=?',(ROW[0],));db.commit()
            self.assertEqual(db.execute('select count(*) from policy_records').fetchone()[0],0)
            self.assertEqual(db.execute('select count(*) from revocation_records').fetchone()[0],0);db.close()
    def test_revocation_constraints(self):
        with sqlite3.connect(':memory:') as db:
            self.setup(db)
            for row in [('d'*32,0),(ROW[0],2)]:
                with self.assertRaises(sqlite3.IntegrityError):db.execute('insert into revocation_records values(?,?)',row)
    def test_offline_cleanup_plan_durable_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'state.sqlite3')
            db=sqlite3.connect(path);self.setup(db)
            old=ROW[0];new='d'*32
            db.execute('update enrollment_records set state=1 where credential=?',(old,))
            db.execute('insert into policy_records values(?,?)',(old,b'old-policy'))
            db.execute('insert into revocation_records values(?,0)',(old,))
            db.execute('insert into enrollment_records values(?,?,?,?,?,?,?)',(new,ROW[1],'e'*32,0,b'new-pending',100,86500))
            db.execute('insert into enrollment_cleanup values(?,?)',(new,old));db.commit();db.close()
            db=sqlite3.connect(path);db.execute('pragma foreign_keys=on')
            self.assertEqual(db.execute('select * from enrollment_cleanup').fetchall(),[(new,old)])
            def activate():
                db.execute('update enrollment_records set state=1 where credential=?',(new,))
                db.execute('insert into policy_records values(?,?)',(new,b'new-policy'))
                db.execute('update revocation_records set acknowledged=1 where credential=?',(old,))
                db.execute('delete from enrollment_cleanup where new_credential=?',(new,))
            activate();db.rollback();db.close()
            db=sqlite3.connect(path);db.execute('pragma foreign_keys=on')
            self.assertEqual(db.execute('select state from enrollment_records where credential=?',(new,)).fetchone()[0],0)
            self.assertEqual(db.execute('select acknowledged from revocation_records').fetchone()[0],0)
            activate();db.commit()
            self.assertEqual(db.execute('select acknowledged from revocation_records').fetchone()[0],1)
            self.assertEqual(db.execute('select count(*) from enrollment_cleanup').fetchone()[0],0)
            db.execute('delete from enrollment_records where credential=?',(old,));db.commit()
            self.assertEqual(db.execute('select credential from enrollment_records').fetchall(),[(new,)])
            db.close()
    def test_cleanup_links_require_durable_revocation(self):
        with sqlite3.connect(':memory:') as db:
            self.setup(db)
            new='d'*32
            db.execute('insert into enrollment_records values(?,?,?,?,?,?,?)',(new,'f'*32,'e'*32,0,b'new',100,86500))
            with self.assertRaises(sqlite3.IntegrityError):db.execute('insert into enrollment_cleanup values(?,?)',(new,ROW[0]))
            db.execute('update enrollment_records set state=1 where credential=?',(ROW[0],))
            db.execute('insert into revocation_records values(?,0)',(ROW[0],))
            with self.assertRaises(sqlite3.IntegrityError):db.execute('insert into enrollment_cleanup values(?,?)',(ROW[0],ROW[0]))
            db.execute('insert into enrollment_cleanup values(?,?)',(new,ROW[0]))
            db.execute('delete from enrollment_records where credential=?',(new,))
            self.assertEqual(db.execute('select count(*) from enrollment_cleanup').fetchone()[0],0)
            self.assertEqual(db.execute('select acknowledged from revocation_records').fetchone()[0],0)
if __name__=='__main__':unittest.main(verbosity=2)

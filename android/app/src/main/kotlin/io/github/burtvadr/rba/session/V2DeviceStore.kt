package io.github.burtvadr.rba.session

import android.content.ContentValues
import android.content.Context
import android.database.DatabaseErrorHandler
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteDatabaseCorruptException
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.protocol.V2PolicySync
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.KeyStore
import io.github.burtvadr.rba.keystore.V2HardwareKeys

/** App-private, non-backed-up, versioned V2 credential storage. Automatic initialization is limited to
 * genuinely fresh state. No V1 reader or destructive migration.
 * The active runtime does not use this store until the coordinated V2 cutover.
 *
 * Key aliases are derived from the credential ID and role. The B.3 key
 * generator creates fresh aliases, checks local hardware policy and never
 * overwrites them. The store rechecks both role keys; this is not a substitute
 * for host-side remote attestation.
 */
internal class V2DeviceStore private constructor(private val db:SQLiteDatabase) : V2Enrollment.PendingStore, AutoCloseable {
    companion object {
        private const val APP_ID=0x52424132L
        private const val VERSION=2L
        private const val MAX_RECORDS=64L
        private const val TABLE="enrollment_records"
        private const val SCHEMA="""CREATE TABLE enrollment_records (
 credential TEXT PRIMARY KEY NOT NULL CHECK(typeof(credential)='text' AND length(credential)=32),
 host TEXT NOT NULL CHECK(typeof(host)='text' AND length(host)=32),
 enrollment TEXT NOT NULL UNIQUE CHECK(typeof(enrollment)='text' AND length(enrollment)=32),
 state INTEGER NOT NULL CHECK(typeof(state)='integer' AND state IN (0,1)),
 record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record) BETWEEN 1 AND 65536),
 created INTEGER NOT NULL CHECK(typeof(created)='integer' AND created>=0),
 recover_until INTEGER NOT NULL CHECK(typeof(recover_until)='integer' AND recover_until>created AND recover_until-created=86400)
)"""
        private const val POLICY_SCHEMA="""CREATE TABLE policy_records (
 credential TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_records(credential) ON DELETE CASCADE,
 snapshot BLOB NOT NULL CHECK(typeof(snapshot)='blob' AND length(snapshot) BETWEEN 1 AND 65536)
)"""
        private const val REVOCATION_SCHEMA="""CREATE TABLE revocation_records (
 credential TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_records(credential) ON DELETE CASCADE,
 acknowledged INTEGER NOT NULL CHECK(typeof(acknowledged)='integer' AND acknowledged IN (0,1))
)"""
        private const val CLEANUP_SCHEMA="""CREATE TABLE enrollment_cleanup (
 new_credential TEXT NOT NULL REFERENCES enrollment_records(credential) ON DELETE CASCADE,
 old_credential TEXT NOT NULL UNIQUE REFERENCES revocation_records(credential) ON DELETE CASCADE,
 PRIMARY KEY(new_credential,old_credential),
 CHECK(new_credential<>old_credential)
)"""
        private const val INDEX="CREATE UNIQUE INDEX pending_per_host ON enrollment_records(host) WHERE state=0"
        private fun hex(id:ByteArray):String {
            require(id.size==16&&id.any{it!=0.toByte()});return id.joinToString(""){"%02x".format(it.toInt() and 255)}
        }
        private fun decodeId(value:String):ByteArray {
            require(value.matches(Regex("[0-9a-f]{32}")))
            return value.chunked(2).map{it.toInt(16).toByte()}.toByteArray().also{check(hex(it)==value)}
        }
        fun transportAlias(credential:ByteArray)="rba-v2-${hex(credential)}-transport"
        fun biometricAlias(credential:ByteArray)="rba-v2-${hex(credential)}-biometric"
        private fun directory(context:Context)=File(context.noBackupFilesDir,"rba-v2")
        private fun path(context:Context)=File(directory(context),"state.sqlite3")
        private fun query(db:SQLiteDatabase,sql:String):String = db.rawQuery(sql,null).use { check(it.moveToFirst());val value=it.getString(0);check(!it.moveToNext());value }
        private fun configure(db:SQLiteDatabase){
            // No WAL or asynchronous fallback; one serialized writer and durable rollback journal.
            check(query(db,"PRAGMA journal_mode=DELETE").equals("delete",ignoreCase=true))
            db.execSQL("PRAGMA foreign_keys=ON")
            check(query(db,"PRAGMA foreign_keys")=="1")
            db.execSQL("PRAGMA synchronous=EXTRA")
            check(query(db,"PRAGMA synchronous").toLong()==3L)
        }
        private fun validate(db:SQLiteDatabase){
            check(query(db,"PRAGMA application_id").toLong()==APP_ID)
            check(query(db,"PRAGMA user_version").toLong()==VERSION)
            check(query(db,"PRAGMA quick_check(1)")=="ok")
            // No writable triggers, alternate tables, or modified schema.
            val rows=db.rawQuery("SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type,name",null).use{ c ->
                buildList{while(c.moveToNext())add(Triple(c.getString(0),c.getString(1),c.getString(2)))}
            }
            // Android may create android_metadata for locale bookkeeping even
            // when localized collators are disabled; it holds no trust state.
            val securityRows=rows.filterNot{it.first=="table"&&it.second=="android_metadata"}
            check(securityRows==listOf(Triple("index","pending_per_host",INDEX),Triple("table","enrollment_cleanup",CLEANUP_SCHEMA),Triple("table",TABLE,SCHEMA),Triple("table","policy_records",POLICY_SCHEMA),Triple("table","revocation_records",REVOCATION_SCHEMA)))
            check(db.rawQuery("PRAGMA foreign_key_check",null).use{!it.moveToFirst()})
            check(query(db,"SELECT count(*) FROM enrollment_cleanup c JOIN enrollment_records n ON n.credential=c.new_credential JOIN enrollment_records o ON o.credential=c.old_credential WHERE n.state<>0 OR o.state<>1 OR n.host<>o.host")=="0")
            check(query(db,"SELECT count(*) FROM revocation_records r JOIN enrollment_records e ON e.credential=r.credential WHERE e.state<>1")=="0")
            check(query(db,"SELECT count(*) FROM enrollment_records e LEFT JOIN policy_records p ON p.credential=e.credential WHERE (e.state=1 AND p.credential IS NULL) OR (e.state=0 AND p.credential IS NOT NULL)")=="0")
        }
        private fun openFile(file:File):SQLiteDatabase=SQLiteDatabase.openDatabase(file.absolutePath,null,SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.NO_LOCALIZED_COLLATORS,
            DatabaseErrorHandler { throw SQLiteDatabaseCorruptException("V2 state corrupt; explicit recovery required") })
        /** Absence of a DB alone is not evidence of a fresh installation.
         * Preserve any existing directory (including incomplete initialization)
         * or V2 key aliases. A failed filesystem/Keystore probe is a hard error. */
        fun openOrInitializeFresh(context:Context):V2DeviceStore {
            val dir=directory(context)
            val opts=arrayOf(LinkOption.NOFOLLOW_LINKS)
            if (Files.exists(dir.toPath(), *opts)) return open(context)
            check(Files.notExists(dir.toPath(), *opts)) { "Cannot determine V2 store state" }
            val keys=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
            check(!keys.aliases().asSequence().any{it.startsWith("rba-v2-")}) {
                "V2 keys exist without their store; recovery required"
            }
            return initialize(context)
        }
        /** Explicit creation primitive. An interrupted or missing
         * existing store must be handled as a recovery error, never reset. */
        fun initialize(context:Context):V2DeviceStore {
            val dir=directory(context);check(dir.mkdir());val file=path(context);check(file.createNewFile())
            val db=openFile(file)
            try {
                configure(db);db.beginTransaction()
                try{db.execSQL(SCHEMA);db.execSQL(INDEX);db.execSQL(POLICY_SCHEMA);db.execSQL(REVOCATION_SCHEMA);db.execSQL(CLEANUP_SCHEMA);db.execSQL("PRAGMA application_id=$APP_ID");db.execSQL("PRAGMA user_version=$VERSION");db.setTransactionSuccessful()}
                finally{db.endTransaction()}
                validate(db);return V2DeviceStore(db)
            }catch(e:Exception){db.close();throw e}
        }
        fun open(context:Context):V2DeviceStore {
            val dir=directory(context); val file=path(context)
            check(Files.isDirectory(dir.toPath(),LinkOption.NOFOLLOW_LINKS) && Files.isRegularFile(file.toPath(),LinkOption.NOFOLLOW_LINKS) && file.length()>0L)
            val db=openFile(file)
            try{configure(db);validate(db);return V2DeviceStore(db)}catch(e:Exception){db.close();throw e}
        }
        private fun checkKeys(p:V2Enrollment.Pending){
            V2HardwareKeys.load(p.credentialId(),p.transportKey(),p.biometricKey())
        }
        private fun checkFresh(p:V2Enrollment.Pending){val now=System.currentTimeMillis()/1000;check(now>=p.createdAt()&&now<p.recoverUntil())}
    }
    private inline fun <T> transaction(block:()->T):T{
        db.beginTransaction();try{val value=block();db.setTransactionSuccessful();return value}finally{db.endTransaction()}
    }
    private fun record(credential:ByteArray,state:Int,usable:Boolean=false):ByteArray?=db.query(TABLE,arrayOf("record"),
        "credential=? AND state=?"+if(usable)" AND NOT EXISTS(SELECT 1 FROM revocation_records r WHERE r.credential=enrollment_records.credential)" else "",
        arrayOf(hex(credential),state.toString()),null,null,null).use{c->
        if(!c.moveToFirst())null else c.getBlob(0).also{check(!c.moveToNext())}
    }
    /** A returned stage call means SQLite committed the exact pending blob.
     * A second staged enrollment for the same host, or reused credential or
     * enrollment ID, fails rather than silently overwriting anything. */
    @Synchronized override fun stage(record:ByteArray)=stageWithCleanup(record,emptyList())
    /** The exact old records whose tokens were sent after confirmed same-host
     * PAKE. The plan is durable before ENROLL_STAGED, including lost receipts. */
    @Synchronized fun stageWithCleanup(record:ByteArray,cleanup:List<V2Enrollment.Pending>){
        val p=V2Enrollment.Pending.decode(record);checkFresh(p);checkKeys(p)
        transaction{
            check(query(db,"SELECT count(*) FROM enrollment_records").toLong()<MAX_RECORDS)
            val values=ContentValues().apply{
                put("credential",hex(p.credentialId()));put("host",hex(p.hostId()));put("enrollment",hex(p.enrollmentId()));put("state",0);put("record",p.encode());put("created",p.createdAt());put("recover_until",p.recoverUntil())
            }
            db.insertOrThrow(TABLE,null,values)
            check(cleanup.size<=32)
            for(old in cleanup){
                check(old.hostId().contentEquals(p.hostId())&&old.hostKey().contentEquals(p.hostKey()))
                check(revoking(old.credentialId()).encode().contentEquals(old.encode()))
                db.insertOrThrow("enrollment_cleanup",null,ContentValues().apply{
                    put("new_credential",hex(p.credentialId()));put("old_credential",hex(old.credentialId()))
                })
            }
        }
    }
    /** Compare-and-set: only the exact, still-pending record can activate.
     * Host receipt verification occurs in V2Enrollment before this call.
     * Other active records are never inherited, overwritten or expanded. */
    @Synchronized override fun activate(expectedPending:ByteArray){
        val p=V2Enrollment.Pending.decode(expectedPending);checkFresh(p);checkKeys(p)
        transaction{
            check(record(p.credentialId(),0)?.contentEquals(p.encode())==true)
            val changed=db.update(TABLE,ContentValues().apply{put("state",1)},"credential=? AND state=0",arrayOf(hex(p.credentialId())))
            check(changed==1)
            db.insertOrThrow("policy_records",null,ContentValues().apply{put("credential",hex(p.credentialId()));put("snapshot",p.initialSnapshot().encode())})
            // Host commits all submitted cleanup tokens in the same enrollment
            // transaction. Receipt recovery takes this identical activation path.
            val oldIds=db.query("enrollment_cleanup",arrayOf("old_credential"),"new_credential=?",arrayOf(hex(p.credentialId())),null,null,null).use{c->buildList{while(c.moveToNext())add(c.getString(0))}}
            for(oldId in oldIds){
                val id=decodeId(oldId)
                val old=V2Enrollment.Pending.decode(checkNotNull(record(id,1)))
                check(old.credentialId().contentEquals(id)&&old.hostId().contentEquals(p.hostId())&&old.hostKey().contentEquals(p.hostKey()))
                check(db.update("revocation_records",ContentValues().apply{put("acknowledged",1)},"credential=?",arrayOf(oldId))==1)
            }
            check(db.delete("enrollment_cleanup","new_credential=?",arrayOf(hex(p.credentialId())))==oldIds.size)

        }
    }
    /** Pending records are for status recovery only; never an auth policy. */
    @Synchronized fun pending(credential:ByteArray):V2Enrollment.Pending?=record(credential,0)?.let{
        V2Enrollment.Pending.decode(it).also{p->checkFresh(p);checkKeys(p);check(p.credentialId().contentEquals(credential))}
    }
    /** The B.3 adapter must additionally enforce local policy, key assurance
     * and authenticated host/session binding before any signature operation. */
    @Synchronized fun active(credential:ByteArray):V2Enrollment.Pending?=record(credential,1,usable=true)?.let{
        V2Enrollment.Pending.decode(it).also{p->checkKeys(p);check(p.credentialId().contentEquals(credential))}
    }
    private fun policyBytes(credential:ByteArray):ByteArray=db.rawQuery("SELECT p.snapshot FROM policy_records p JOIN enrollment_records e ON e.credential=p.credential WHERE e.state=1 AND p.credential=? AND NOT EXISTS(SELECT 1 FROM revocation_records r WHERE r.credential=e.credential)",arrayOf(hex(credential))).use{c->check(c.moveToFirst());c.getBlob(0).also{check(!c.moveToNext())}}
    @Synchronized fun policySnapshot(credential:ByteArray):V2PolicySync.Snapshot {
        val enrollment=checkNotNull(active(credential));val snapshot=V2PolicySync.Snapshot.decode(policyBytes(credential))
        check(snapshot.credential().contentEquals(credential)&&snapshot.host().contentEquals(enrollment.hostId()))
        return snapshot
    }
    /** Called only by the same-channel policy receipt handler. The enrollment
     * record never changes, so its recovery hash remains immutable. */
    @Synchronized fun commitPolicy(credential:ByteArray,expected:ByteArray,next:ByteArray){
        val prior=V2PolicySync.Snapshot.decode(expected);val proposed=V2PolicySync.Snapshot.decode(next)
        check(prior.credential().contentEquals(credential)&&proposed.credential().contentEquals(credential)&&prior.host().contentEquals(proposed.host()))
        check(prior.owner()?.let{proposed.owner()?.contentEquals(it)==true}?:true)
        check(proposed.revision>prior.revision || (proposed.revision==prior.revision&&next.contentEquals(expected)))
        transaction{
            check(policySnapshot(credential).encode().contentEquals(expected))
            check(db.update("policy_records",ContentValues().apply{put("snapshot",proposed.encode())},"credential=?",arrayOf(hex(credential)))==1)
        }
    }
    private fun revocationState(credential:ByteArray):Int?=db.query("revocation_records",arrayOf("acknowledged"),"credential=?",arrayOf(hex(credential)),null,null,null).use{c->
        if(!c.moveToFirst())null else c.getInt(0).also{check(!c.moveToNext())}
    }
    /** Durable local denial precedes any network attempt. Idempotent across
     * restart. Never require a working biometric key to disable a credential. */
    @Synchronized fun beginRevocation(credential:ByteArray){
        transaction{
            check(record(credential,1)!=null)
            if(revocationState(credential)==null)db.insertOrThrow("revocation_records",null,ContentValues().apply{put("credential",hex(credential));put("acknowledged",0)})
        }
    }
    /** Original unpair action addresses a host, which can own several V2
     * credentials. Deny all in one transaction; no partial local result. */
    @Synchronized fun beginHostRevocation(hostId:String){
        decodeId(hostId)
        transaction{
            val active=inventory().filter{it.host==hostId&&it.state==RecordState.ACTIVE}
            check(active.isNotEmpty())
            val pins=active.map{V2Enrollment.Pending.decode(checkNotNull(record(decodeId(it.credential),1))).hostKey().toList()}.distinct()
            check(pins.size==1){"Ambiguous host identity"}
            for(row in active)db.insertOrThrow("revocation_records",null,ContentValues().apply{put("credential",row.credential);put("acknowledged",0)})
        }
    }
    @Synchronized fun revocationAcknowledged(credential:ByteArray):Boolean=checkNotNull(revocationState(credential))==1
    /** Only the revocation TLS owner may load this record. No auth or policy
     * path can see it through active(), even if the network is offline. */
    @Synchronized fun revoking(credential:ByteArray):V2Enrollment.Pending {
        check(revocationState(credential)==0)
        val p=V2Enrollment.Pending.decode(checkNotNull(record(credential,1)))
        check(p.credentialId().contentEquals(credential));return p
    }
    /** Only after exact authenticated receipt validation. A failed commit
     * leaves the credential disabled and eligible for authenticated retry. */
    @Synchronized fun acknowledgeRevocation(credential:ByteArray,expected:ByteArray){
        transaction{
            check(record(credential,1)?.contentEquals(expected)==true)
            check(db.update("revocation_records",ContentValues().apply{put("acknowledged",1)},"credential=? AND acknowledged=0",arrayOf(hex(credential)))==1)
        }
    }
    /** Commit acknowledgment first, delete exact keys second, delete record
     * last. If either cleanup step fails the acknowledged record survives and
     * restart can retry without TLS or access to deleted keys. */
    @Synchronized fun finishRevocationCleanup(credential:ByteArray){
        check(revocationState(credential)==1)
        val p=V2Enrollment.Pending.decode(checkNotNull(record(credential,1)))
        check(p.credentialId().contentEquals(credential))
        V2HardwareKeys.deleteInaccessible(credential,p.transportKey(),p.biometricKey())
        transaction{
            check(revocationState(credential)==1&&record(credential,1)?.contentEquals(p.encode())==true)
            check(db.delete(TABLE,"credential=? AND state=1",arrayOf(hex(credential)))==1)
        }
    }
    private fun recorded(credential:ByteArray):Boolean = db.query(TABLE,arrayOf("credential"),"credential=?",arrayOf(hex(credential)),null,null,null).use{it.moveToFirst()}
    /** Only the serialized enrollment owner can create keys. No record grants
     * trust until V2Enrollment has processed the authenticated receipt. */
    @Synchronized fun generateEnrollmentKeys(context:Context,challenges:V2Enrollment.Challenges):V2HardwareKeys.Credential {
        val keys=V2HardwareKeys.generate(context,challenges)
        if(recorded(keys.id())) {
            // Extremely unlikely random ID collision with a record whose keys
            // are absent. The new keys do not belong to that record.
            V2HardwareKeys.deleteUnrecorded(keys.id(),keys.transportPoint(),keys.biometricPoint())
            error("Credential ID already recorded")
        }
        return keys
    }
    /** Cancel before durable staging. Never delete keys for pending or active
     * records, including an enrollment whose stage outcome is uncertain. */
    @Synchronized fun discardUnrecorded(keys:V2HardwareKeys.Credential){
        check(!recorded(keys.id()))
        V2HardwareKeys.deleteUnrecorded(keys.id(),keys.transportPoint(),keys.biometricPoint())
    }
    /** On an interrupted stage/ack, preserve any durable record. Failure to
     * query the database is not evidence that its keys are unrecorded. */
    @Synchronized fun discardIfUnrecorded(keys:V2HardwareKeys.Credential){
        if(!recorded(keys.id())) discardUnrecorded(keys)
    }
    /** Explicit local discard only. If host may have committed, operator must
     * revoke/re-enroll on host. No active record is deleted by this operation. */
    @Synchronized fun discardPending(credential:ByteArray,expectedPending:ByteArray){
        val p=V2Enrollment.Pending.decode(expectedPending);check(p.credentialId().contentEquals(credential))
        transaction{check(record(credential,0)?.contentEquals(p.encode())==true);check(db.delete(TABLE,"credential=? AND state=0",arrayOf(hex(credential)))==1)}
        // The record is already inaccessible if key deletion fails. Never
        // restore the record or delete keys before the transaction commits.
        check(!recorded(credential))
        V2HardwareKeys.deleteUnrecorded(credential,p.transportKey(),p.biometricKey())
    }
    /** Called under the process-wide operation owner, before accepting any
     * operation. Never infer absence from a failed/partial database read. */
    @Synchronized fun reclaimAtExclusiveStartup(){
        validate(db)
        val all=db.query(TABLE,arrayOf("credential","host","enrollment","record","state","created","recover_until"),null,null,null,null,null).use{c->buildList{
            while(c.moveToNext()){
                val id=decodeId(c.getString(0));val p=V2Enrollment.Pending.decode(c.getBlob(3))
                check(p.credentialId().contentEquals(id)&&hex(p.hostId())==c.getString(1)&&hex(p.enrollmentId())==c.getString(2))
                check(c.getInt(4) in 0..1&&p.createdAt()==c.getLong(5)&&p.recoverUntil()==c.getLong(6))
                add(id)
            }
        }}
        val acknowledged=all.filter{revocationState(it)==1}
        for(id in acknowledged)finishRevocationCleanup(id)
        // Keep every recorded key, even if expired, invalidated or pending.
        // Keystore aliases cannot outlive a successful complete DB inventory
        // unless they are referenced by one of those durable records.
        V2HardwareKeys.reclaimUnrecordedAliases(all.filterNot{id->acknowledged.any{it.contentEquals(id)}}.map{hex(it)}.toSet())
    }
    enum class RecordState { PENDING, ACTIVE, REVOKING, CLEANUP }
    data class Summary(val credential: String, val host: String, val state: RecordState)
    /** Metadata only. Never load key material or return enrollment tokens to UI. */
    @Synchronized fun inventory(): List<Summary> = db.rawQuery("SELECT e.credential,e.host,e.state,r.acknowledged FROM enrollment_records e LEFT JOIN revocation_records r ON r.credential=e.credential ORDER BY e.host,e.credential",null).use{c->buildList{
        while(c.moveToNext()) {
            val id=hex(decodeId(c.getString(0))); val host=hex(decodeId(c.getString(1)))
            val state=if(c.getInt(2)==0)RecordState.PENDING else if(c.isNull(3))RecordState.ACTIVE else if(c.getInt(3)==0)RecordState.REVOKING else RecordState.CLEANUP
            add(Summary(id,host,state))
        }
    }}
    data class Route(val summary:Summary,val hostPoint:ByteArray,val location:V2HardwareKeys.Location?)
    /** Metadata snapshot: never substitutes for load/policy/TLS verification. */
    @Synchronized fun routes():List<Route> = inventory().map{summary->
        val id=decodeId(summary.credential)
        val p=V2Enrollment.Pending.decode(checkNotNull(record(id,if(summary.state==RecordState.PENDING)0 else 1)))
        check(p.credentialId().contentEquals(id)&&hex(p.hostId())==summary.host)
        val location=if(summary.state==RecordState.ACTIVE)runCatching{
            V2HardwareKeys.load(id,p.transportKey(),p.biometricKey()).biometricLocation
        }.getOrNull()else null
        Route(summary,p.hostKey(),location)
    }
    @Synchronized override fun close(){db.close()}
}

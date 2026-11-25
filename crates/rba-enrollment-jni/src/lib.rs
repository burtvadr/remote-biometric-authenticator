//! Narrow Android JNI boundary. No pointers or session keys cross the ABI.
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use jni::{JNIEnv, objects::{JByteArray, JClass}, sys::{jbyteArray, jlong}};
use rba_enrollment::{Context, DeviceExchange, PairingCode};
use zeroize::Zeroizing;

// Android permits one enrollment at a time. Handles are never reused; stale
// cancel/finish calls cannot act on a newer session. Cancellation drops secrets.
static ACTIVE: Mutex<Option<(i64, DeviceExchange)>> = Mutex::new(None);
static NEXT: AtomicI64 = AtomicI64::new(1);

fn failure(env: &mut JNIEnv) -> jbyteArray {
    let _ = env.throw_new("java/lang/IllegalStateException", "native enrollment rejected");
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "system" fn Java_io_github_burtvadr_rba_session_NativeEnrollment_generateCode(
    mut env: JNIEnv, _: JClass,
) -> jbyteArray {
    let result = PairingCode::generate().ok().and_then(|code| env.byte_array_from_slice(code.as_ascii()).ok());
    match result { Some(array) => array.into_raw(), None => failure(&mut env) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_burtvadr_rba_session_NativeEnrollment_startDevice(
    mut env: JNIEnv, _: JClass, code: JByteArray, context: JByteArray,
) -> jbyteArray {
    let result = (|| {
        if env.get_array_length(&code).ok()? != 6 || env.get_array_length(&context).ok()? != Context::ENCODED_LEN as i32 { return None; }
        let code = Zeroizing::new(env.convert_byte_array(&code).ok()?);
        let context = Context::from_binding_bytes(&env.convert_byte_array(&context).ok()?).ok()?;
        let code = PairingCode::parse(&code).ok()?;
        let mut active = ACTIVE.lock().ok()?;
        if active.is_some() { return None; }
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (share, exchange) = rba_enrollment::start_device(code, &context, &mut rng).ok()?;
        let handle = NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)).ok()?;
        let mut out = handle.to_be_bytes().to_vec();
        out.extend_from_slice(&share);
        let array = env.byte_array_from_slice(&out).ok()?;
        *active = Some((handle, exchange));
        Some(array)
    })();
    match result { Some(array) => array.into_raw(), None => failure(&mut env) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_burtvadr_rba_session_NativeEnrollment_finishDevice(
    mut env: JNIEnv, _: JClass, handle: jlong, share: JByteArray, tag: JByteArray,
) -> jbyteArray {
    let result = (|| {
        // Consume the matching state before validating anything supplied by the peer.
        let exchange = {
            let mut active = ACTIVE.lock().ok()?;
            if active.as_ref().map(|v| v.0) != Some(handle) { return None; }
            active.take()?.1
        };
        if env.get_array_length(&share).ok()? != 65 || env.get_array_length(&tag).ok()? != 32 { return None; }
        let share = env.convert_byte_array(&share).ok()?;
        let tag = env.convert_byte_array(&tag).ok()?;
        let proof = rba_enrollment::finish_device(exchange, &share, &tag).ok()?;
        env.byte_array_from_slice(&proof).ok()
    })();
    match result { Some(array) => array.into_raw(), None => failure(&mut env) }
}

#[no_mangle]
pub extern "system" fn Java_io_github_burtvadr_rba_session_NativeEnrollment_cancelDevice(
    _: JNIEnv, _: JClass, handle: jlong,
) {
    if let Ok(mut active) = ACTIVE.lock() {
        if active.as_ref().map(|v| v.0) == Some(handle) { active.take(); }
    }
}

// V2 uses the same single-use slot and handle allocator as the existing
// primitive. No key material or native pointer is returned to Kotlin.
#[no_mangle]
pub extern "system" fn Java_io_github_burtvadr_rba_session_NativeEnrollment_startDeviceV2(
    mut env: JNIEnv, _: JClass, code: JByteArray, host: JByteArray, credential: JByteArray, aad: JByteArray,
) -> jbyteArray {
    let result = (|| {
        if env.get_array_length(&code).ok()? != 6 || env.get_array_length(&host).ok()? != 16 || env.get_array_length(&credential).ok()? != 16 || !(1..=4096).contains(&env.get_array_length(&aad).ok()?) { return None; }
        let code = Zeroizing::new(env.convert_byte_array(&code).ok()?);
        let host: [u8;16] = env.convert_byte_array(&host).ok()?.try_into().ok()?;
        let credential: [u8;16] = env.convert_byte_array(&credential).ok()?.try_into().ok()?;
        let aad = env.convert_byte_array(&aad).ok()?;
        let mut active = ACTIVE.lock().ok()?;
        if active.is_some() { return None; }
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (share, exchange) = rba_enrollment::start_device_v2(PairingCode::parse(&code).ok()?, &host, &credential, &aad, &mut rng).ok()?;
        let handle = NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)).ok()?;
        let mut out = handle.to_be_bytes().to_vec(); out.extend_from_slice(&share);
        let array = env.byte_array_from_slice(&out).ok()?;
        *active = Some((handle, exchange)); Some(array)
    })();
    match result { Some(array) => array.into_raw(), None => failure(&mut env) }
}

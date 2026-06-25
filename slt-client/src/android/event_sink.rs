use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::Arc;

use jni::objects::{GlobalRef, JObject, JObjectArray, JString, JValue, JValueGen};
use jni::sys::jint;
use jni::{JNIEnv, JavaVM};
use tracing::debug;

use crate::transport::host_resolver::{HostResolver, HostResolverFuture, ensure_non_empty};
use crate::transport::socket_protector::{SocketKind, SocketProtector};

#[derive(Clone)]
pub(super) struct EventSink {
    inner: Arc<EventSinkInner>,
}

struct EventSinkInner {
    vm: JavaVM,
    callback: GlobalRef,
}

pub(super) struct AndroidSocketProtector {
    sink: EventSink,
}

pub(super) struct AndroidHostResolver {
    sink: EventSink,
}

impl AndroidSocketProtector {
    pub(super) fn new(sink: EventSink) -> Self {
        Self { sink }
    }
}

impl AndroidHostResolver {
    pub(super) fn new(sink: EventSink) -> Self {
        Self { sink }
    }
}

impl SocketProtector for AndroidSocketProtector {
    fn protect(&self, fd: RawFd, kind: SocketKind) -> io::Result<()> {
        self.sink.protect_socket(fd, kind)
    }
}

impl HostResolver for AndroidHostResolver {
    fn resolve<'a>(&'a self, hostname: &'a str, port: u16) -> HostResolverFuture<'a> {
        let sink = self.sink.clone();
        let hostname = hostname.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || sink.resolve_host(&hostname, port))
                .await
                .map_err(|err| io::Error::other(format!("Android DNS task failed: {err}")))?
        })
    }
}

impl EventSink {
    pub(super) fn new(vm: JavaVM, callback: GlobalRef) -> Self {
        Self {
            inner: Arc::new(EventSinkInner { vm, callback }),
        }
    }

    pub(super) fn status(&self, status: &str, detail: Option<&str>) {
        self.call(
            "onStatus",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            status,
            detail,
        );
    }

    fn protect_socket(&self, fd: RawFd, kind: SocketKind) -> io::Result<()> {
        let mut env = self.inner.vm.attach_current_thread().map_err(|err| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("attach JNI thread for socket protection: {err}"),
            )
        })?;
        let fd = jint::try_from(fd).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("socket fd out of JNI int range: {fd}"),
            )
        })?;

        let protected = env
            .call_method(
                self.inner.callback.as_obj(),
                "protectSocket",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .and_then(JValueGen::z)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("call Android protectSocket for {kind:?} fd {fd}: {err}"),
                )
            })?;

        if protected {
            debug!(fd, kind = ?kind, "Android socket protected");
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Android protectSocket returned false for {kind:?} fd {fd}"),
            ))
        }
    }

    fn resolve_host(&self, hostname: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let mut env = self.inner.vm.attach_current_thread().map_err(|err| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("attach JNI thread for host resolution: {err}"),
            )
        })?;
        let hostname_arg = env.new_string(hostname).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("create host resolution argument: {err}"),
            )
        })?;
        let hostname_arg = JObject::from(hostname_arg);

        let resolved = match env
            .call_method(
                self.inner.callback.as_obj(),
                "resolveHost",
                "(Ljava/lang/String;)[Ljava/lang/String;",
                &[JValue::Object(&hostname_arg)],
            )
            .and_then(JValueGen::l)
        {
            Ok(resolved) => resolved,
            Err(err) => {
                clear_pending_exception(&mut env);
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("call Android resolveHost for {hostname}: {err}"),
                ));
            }
        };
        if resolved.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Android resolveHost returned null for {hostname}"),
            ));
        }

        let resolved = JObjectArray::from(resolved);
        let len = env.get_array_length(&resolved).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("read Android resolveHost result length for {hostname}: {err}"),
            )
        })?;
        let mut addrs = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        for index in 0..len {
            let element = env
                .get_object_array_element(&resolved, index)
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("read Android resolveHost result {index} for {hostname}: {err}"),
                    )
                })?;
            if element.is_null() {
                continue;
            }
            let address = JString::from(element);
            let address: String = env
                .get_string(&address)
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("read Android resolveHost address {index} for {hostname}: {err}"),
                    )
                })?
                .into();
            let ip = address.parse::<IpAddr>().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Android resolveHost returned non-IP address {address}: {err}"),
                )
            })?;
            addrs.push(SocketAddr::new(ip, port));
        }

        ensure_non_empty(addrs)
    }

    fn call(&self, method: &str, signature: &str, first: &str, second: Option<&str>) {
        let Ok(mut env) = self.inner.vm.attach_current_thread() else {
            return;
        };
        let Ok(first) = env.new_string(first) else {
            return;
        };
        let second = match second {
            Some(second) => {
                let Ok(second) = env.new_string(second) else {
                    return;
                };
                JObject::from(second)
            }
            None => JObject::null(),
        };

        let first = JObject::from(first);
        let args = [JValue::Object(&first), JValue::Object(&second)];
        let _ = env.call_method(self.inner.callback.as_obj(), method, signature, &args);
    }
}

fn clear_pending_exception(env: &mut JNIEnv<'_>) {
    if matches!(env.exception_check(), Ok(true)) {
        let _ = env.exception_clear();
    }
}

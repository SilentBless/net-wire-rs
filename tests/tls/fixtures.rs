use net_wire::tls::{TlsExtension, TlsExtensions};

pub(crate) fn only_extension(bytes: &[u8]) -> TlsExtension<'_> {
    let mut extensions = TlsExtensions::new(bytes);
    let extension = extensions.next().expect("fixture extension").unwrap();
    assert!(extensions.next().is_none());
    extension
}

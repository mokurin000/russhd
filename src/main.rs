use async_scoped::spawner::use_tokio::Tokio;
use key::ed25519::SecretKey;
use ssh_key::private::Ed25519Keypair;
use ssh_key::PrivateKey;
use std::collections::HashMap;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use thrussh::server::{Auth, Session};
use thrussh::*;
use thrussh_keys::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init_timed();

    let client_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
    let client_pubkey = Arc::new(client_key.clone_public_key());
    let mut config = thrussh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(3));
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config
        .keys
        .push(thrussh_keys::key::KeyPair::generate_ed25519().unwrap());
    let config = Arc::new(config);
    let sh = Server {
        client_pubkey,
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };

    match client_key {
        key::KeyPair::Ed25519(secret_key) => {
            show_secret_key(secret_key)?;
        }
    }

    thrussh::server::run(config, "0.0.0.0:2281", sh).await?;
    Ok(())
}

#[derive(Clone)]
struct Server {
    #[allow(dead_code)]
    client_pubkey: Arc<thrussh_keys::key::PublicKey>,
    clients: Arc<Mutex<HashMap<(usize, ChannelId), thrussh::server::Handle>>>,
    id: usize,
}

impl server::Server for Server {
    type Handler = Self;
    fn new(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
}

impl server::Handler for Server {
    type Error = anyhow::Error;
    type FutureAuth = futures::future::Ready<Result<(Self, server::Auth), anyhow::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, Session, bool), anyhow::Error>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        futures::future::ready(Ok((self, auth)))
    }
    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        futures::future::ready(Ok((self, s, b)))
    }
    fn finished(self, s: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, s)))
    }
    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        {
            let mut clients = self.clients.lock().unwrap();
            clients.insert((self.id, channel), session.handle());
        }
        self.finished(session)
    }
    fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        self.finished_auth(server::Auth::Accept)
    }
    fn auth_password(self, _: &str, _: &str) -> Self::FutureAuth {
        self.finished_auth(server::Auth::Accept)
    }
    fn data(self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        {
            let mut clients = self.clients.lock().unwrap();
            for ((id, channel), ref mut s) in clients.iter_mut() {
                if *id != self.id {
                    let mut tokio = unsafe { async_scoped::TokioScope::create(Tokio) };
                    tokio.spawn(async {
                        log::info!("spawned data send");
                        let _ = s.data(*channel, CryptoVec::from_slice(data)).await;
                    });
                }
            }
        }
        session.data(channel, CryptoVec::from_slice(data));
        self.finished(session)
    }
}

fn show_secret_key(secret_key: SecretKey) -> anyhow::Result<()> {
    let keypair: Ed25519Keypair = Ed25519Keypair::from_bytes(&secret_key.key)?;
    let ssh_key = PrivateKey::from(keypair).to_openssh(ssh_key::LineEnding::LF)?;
    let ssh_key = ssh_key.as_str();
    eprintln!("{ssh_key}");

    if cfg!(debug_assertions) {
        let _ = fs::set_permissions("priv.key", Permissions::from_mode(0o600));
        fs::write("priv.key", ssh_key)?;
        fs::set_permissions("priv.key", Permissions::from_mode(0o400))?;
        log::info!("SSH key written to priv.key");
    }

    Ok(())
}

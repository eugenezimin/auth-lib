//! Integration test — federation mode end to end on Postgres: the
//! authority on the full schema, a second service on a session-store
//! schema, an in-process transport between them.
//!
//! Run with:
//!   cargo test -p z-auth-postgres --test federation

mod helpers;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use uuid::Uuid;
use z_auth::conf::config::{AuthConfig, RawConfig};
use z_auth::identity::user::RegisterUser;
use z_auth::security::authentication::{ClientContext, Credentials, LoginOutcome};
use z_auth::security::session::SessionStatus;
use z_auth::security::token::keys::{generate_refresh_secret, generate_signing_key};
use z_auth::{AuthError, ZAuth};
use z_auth_cluster::config::{ClusterSettings, RawClusterConfig};
use z_auth_cluster::federation::{Federation, SessionRepositories, SyncStore};
use z_auth_cluster::shared::{ClusterEnvelope, ClusterService, ClusterTransport, NodeInfo};
use z_auth_postgres::{
    PgKeyRepository, PgNodeRepository, PgPermissionRepository, PgRevocationRepository,
    PgSessionRepository, PgSyncStore, repositories,
};

use crate::helpers::{cluster_pool as pool, session_store_pool, unique_email};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
const SECRET: &str = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=";

/// One instance: its `ZAuth` and its federation handle.
struct Instance {
    auth: ZAuth,
    federation: Arc<Federation>,
}

impl Deref for Instance {
    type Target = ZAuth;
    fn deref(&self) -> &ZAuth {
        &self.auth
    }
}

/// Routes envelopes between in-process instances, by node id or address.
#[derive(Default)]
struct Network {
    by_id: Mutex<HashMap<Uuid, Weak<Instance>>>,
    by_addr: Mutex<HashMap<String, Uuid>>,
}

impl Network {
    fn attach(&self, auth: &Arc<Instance>) {
        let local = auth.federation.cluster().unwrap().local();
        self.by_id
            .lock()
            .unwrap()
            .insert(auth.node_id(), Arc::downgrade(auth));
        self.by_addr
            .lock()
            .unwrap()
            .insert(format!("{}:{}", local.host(), local.port), auth.node_id());
    }
}

#[async_trait]
impl ClusterTransport for Network {
    async fn send(
        &self,
        to: &NodeInfo,
        envelope: &ClusterEnvelope,
    ) -> Result<Option<ClusterEnvelope>, AuthError> {
        let unreachable = || AuthError::ClusterUnreachable(to.host());
        let id = if to.node_id.is_nil() {
            *self
                .by_addr
                .lock()
                .unwrap()
                .get(&format!("{}:{}", to.host(), to.port))
                .ok_or_else(unreachable)?
        } else {
            to.node_id
        };
        let target = self
            .by_id
            .lock()
            .unwrap()
            .get(&id)
            .and_then(Weak::upgrade)
            .ok_or_else(unreachable)?;
        target.federation.receive(envelope.clone()).await
    }
}

fn config(
    keys: &RawConfig,
    service: &str,
    authority: &str,
    port: u16,
    seeds: &[String],
) -> (AuthConfig, ClusterSettings) {
    let settings = RawClusterConfig::default()
        .deployment_mode("federation")
        .authority_service(authority)
        .cluster_service(service)
        .cluster_seeds(seeds.iter().cloned())
        .cluster_secret(SECRET)
        .cluster_advertise_ip("127.0.0.1")
        .cluster_advertise_port(port)
        .build()
        .unwrap();
    (keys.clone().build().unwrap(), settings)
}

#[tokio::test]
async fn test_login_at_the_authority_refresh_and_logout_at_a_session_store() {
    let suffix = Uuid::new_v4().simple().to_string();
    let (ums_name, orders_name) = (format!("ums-{suffix}"), format!("orders-{suffix}"));
    let keys = {
        let k = generate_signing_key().unwrap();
        RawConfig::default()
            .jwt_signing_key(k.signing_key)
            .jwt_issuer("z-auth-test")
            .refresh_secret(generate_refresh_secret().unwrap())
    };
    let network = Arc::new(Network::default());

    // The authority: full schema.
    let ums_pool = pool().await;
    let (ums_config, ums_settings) = config(&keys, &ums_name, &ums_name, 7100, &[]);
    let ums_federation = Arc::new(Federation::new(
        ums_settings,
        network.clone(),
        Arc::new(PgNodeRepository::new(ums_pool.clone())),
        Arc::new(PgSyncStore::new(ums_pool.clone())),
    ));
    let ums = Arc::new(Instance {
        auth: ZAuth::builder(ums_config, repositories(&ums_pool))
            .permissions(Arc::new(PgPermissionRepository::new(ums_pool.clone())))
            .extension(ums_federation.clone())
            .build()
            .unwrap(),
        federation: ums_federation,
    });
    network.attach(&ums);
    ums.start().await.unwrap();

    // A session store in its own schema.
    let schema = format!("ss_{suffix}");
    let orders_pool = session_store_pool(&schema).await;
    let orders_sync = Arc::new(PgSyncStore::new(orders_pool.clone()));
    let (orders_config, orders_settings) = config(
        &keys,
        &orders_name,
        &ums_name,
        7200,
        &["127.0.0.1:7100".into()],
    );
    let orders_federation = Arc::new(Federation::new(
        orders_settings,
        network.clone(),
        Arc::new(PgNodeRepository::new(orders_pool.clone())),
        orders_sync.clone(),
    ));
    let orders_repos = orders_federation.session_store_repositories(SessionRepositories {
        sessions: Arc::new(PgSessionRepository::new(orders_pool.clone())),
        revocations: Arc::new(PgRevocationRepository::new(orders_pool.clone())),
        keys: Arc::new(PgKeyRepository::new(orders_pool.clone())),
    });
    let orders = Arc::new(Instance {
        auth: ZAuth::builder(orders_config, orders_repos)
            .extension(orders_federation.clone())
            .build()
            .unwrap(),
        federation: orders_federation,
    });
    network.attach(&orders);
    orders.start().await.unwrap();

    // Identity at the authority only.
    let email = unique_email("federation");
    let password = "Blablabla1!";
    let register = |email: &str| RegisterUser {
        email: email.into(),
        password: password.into(),
        username: None,
        first_name: None,
        last_name: None,
    };
    assert!(matches!(
        orders.users().register(register(&email)).await,
        Err(AuthError::NotAuthority { .. })
    ));
    let user = ums.users().register(register(&email)).await.unwrap();
    let pair = ums
        .authentication()
        .login(
            Credentials {
                email: email.clone(),
                password: password.into(),
            },
            ClientContext::new(IP),
        )
        .await
        .and_then(LoginOutcome::into_tokens)
        .unwrap();

    // Sync: the session store pulls the authority's feed.
    for _ in 0..3 {
        ums.tick().await.unwrap();
        orders.tick().await.unwrap();
    }
    let (copy, _) = orders_sync
        .load_session(pair.session_id)
        .await
        .unwrap()
        .expect("session synced to the session store");
    assert_eq!(copy.session.user_id, user.id);
    assert!(
        orders_sync
            .load_account(user.id)
            .await
            .unwrap()
            .unwrap()
            .is_active
    );

    // Refresh and logout at the session store.
    let next = orders
        .authentication()
        .refresh(
            &pair.access_token,
            &pair.refresh_token,
            ClientContext::new(IP),
        )
        .await
        .unwrap();
    ums.verifier().verify(&next.access_token).unwrap();
    assert!(
        orders
            .authentication()
            .logout(&next.access_token)
            .await
            .unwrap()
    );
    for _ in 0..3 {
        ums.tick().await.unwrap();
        orders.tick().await.unwrap();
    }
    let at_authority = PgSyncStore::new(ums_pool.clone())
        .load_session(pair.session_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(at_authority.session.status, SessionStatus::Revoked);
    assert_eq!(at_authority.session.current_generation, 2);

    // Cleanup.
    ums.shutdown().await.unwrap();
    orders.shutdown().await.unwrap();
    let _ = ums.users().delete(user.id).await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&ums_pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cluster_nodes WHERE service = $1")
        .bind(&ums_name)
        .execute(&ums_pool)
        .await
        .unwrap();
}

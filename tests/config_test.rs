use auth_lib::model::config::{Config, DirectLoader, RawConfig};

#[test]
/// A simple test to verify that the DirectLoader correctly populates the Config
/// struct from a RawConfig, and that all the getters and derived fields work as expected.
/// This also serves as a usage example for the library's configuration system.
/// Note: this test does not cover the EnvLoader or error handling; those are tested separately.
/// To run this test, use `[cargo test config_direct_load]`.
fn config_direct_load() {
    // Create a RawConfig with all fields set, using the builder helpers for convenience.
    // In a real application, you might only set a few fields and rely on defaults for the rest.
    // The values here are arbitrary and just for demonstration purposes.
    let configuration = RawConfig::default()
        .db_host("localhost")
        .db_port(5432)
        .db_user("postgres")
        .db_password("super-secret-db-password")
        .db_name("auth_db")
        .db_max_pool_size(20)
        .db_connect_timeout_secs(10)
        .jwt_secret("my-very-long-jwt-signing-secret")
        .jwt_access_expiry_secs(900) // 15 min
        .jwt_refresh_expiry_secs(604_800) // 7 days
        .jwt_issuer("auth-lib-test")
        .server_host("0.0.0.0")
        .server_port(8080)
        .server_max_body_bytes(2_097_152); // 2 MiB

    // Initialize the global Config using the DirectLoader with our RawConfig.
    let cfg =
        Config::init_with(DirectLoader::new(configuration)).expect("Config::init_with failed");

    // Verify that the global Config is now initialized and contains the expected values.
    assert!(Config::is_initialized());

    // Print out the loaded configuration for manual verification (optional).
    println!("=== DatabaseConfig ===");
    println!("  host              : {}", cfg.database.host);
    println!("  port              : {}", cfg.database.port);
    println!("  user              : {}", cfg.database.user);
    println!("  password          : {}", cfg.database.password);
    println!("  name              : {}", cfg.database.name);
    println!("  max_pool_size     : {}", cfg.database.max_pool_size);
    println!("  connect_timeout   : {:?}", cfg.database.connect_timeout);
    println!("  connection_string : {}", cfg.database.connection_string());
    println!("  connection_url    : {}", cfg.database.connection_url());

    // Print out the JWT configuration for manual verification (optional).
    println!("=== JwtConfig ===");
    println!("  secret                : {}", cfg.jwt.secret);
    println!(
        "  access_token_expiry   : {:?}",
        cfg.jwt.access_token_expiry
    );
    println!(
        "  refresh_token_expiry  : {:?}",
        cfg.jwt.refresh_token_expiry
    );
    println!("  issuer                : {}", cfg.jwt.issuer);
    println!("  access_expiry_secs()  : {}", cfg.jwt.access_expiry_secs());
    println!(
        "  refresh_expiry_secs() : {}",
        cfg.jwt.refresh_expiry_secs()
    );

    // Print out the server configuration for manual verification (optional).
    println!("=== ServerConfig ===");
    println!("  host            : {}", cfg.server.host);
    println!("  port            : {}", cfg.server.port);
    println!("  max_body_bytes  : {}", cfg.server.max_body_bytes);
    println!("  bind_address()  : {}", cfg.server.bind_address());

    // Assert that the values in the global Config match what we set in the RawConfig.
    let global = Config::global();
    assert_eq!(global.database.host, "localhost");
    assert_eq!(global.jwt.issuer, "auth-lib-test");
    assert_eq!(global.server.bind_address(), "0.0.0.0:8080");
}

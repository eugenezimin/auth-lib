//! Configuration sources: the process environment and a YAML file.
//!
//! A [`ConfigSource`] has up to two layers.  The file layer is a YAML
//! document with one top-level section per crate (`auth`, `cluster`, `mfa`,
//! `database`, …); the environment layer is the process environment or a
//! caller-supplied lookup.  When both are present the environment wins, so
//! the file holds the structure and the environment overrides single
//! settings (typically secrets).
//!
//! Every setting is identified by a [`Key`] pairing its environment variable
//! with its dotted path in the file.  Loaders read a crate's settings
//! through a [`Section`], which also rejects keys in the file that the crate
//! does not know.
//!
//! ```rust
//! # #[cfg(feature = "yaml")] {
//! use z_auth::conf::config::{ConfigLoader, ConfigSource, SourceLoader};
//!
//! let source = ConfigSource::yaml_str("auth:\n  jwt:\n    issuer: my-auth\n")
//!     .unwrap()
//!     .with_lookup(|key| (key == "AUTH_JWT_LEEWAY_SECS").then(|| "5".to_string()));
//! let config = SourceLoader::new(source).load_config().unwrap();
//! assert_eq!(config.jwt.issuer, "my-auth");
//! assert_eq!(config.jwt.leeway.as_secs(), 5);
//! # }
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::conf::config::model::ConfigError;
use crate::conf::constants::ENV_CONFIG_FILE;

/// One setting: its environment variable and its dotted path in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub env: &'static str,
    pub path: &'static str,
}

impl Key {
    pub const fn new(env: &'static str, path: &'static str) -> Self {
        Self { env, path }
    }
}

/// A value read from a [`ConfigSource`], with where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The raw text.  A list in the file arrives comma-joined, exactly like
    /// the comma-separated form of the environment variable.
    pub value: String,
    /// The environment variable name, or `<path> in <file>` — used as the
    /// key of a [`ConfigError`] about this value.
    pub origin: String,
}

type Lookup = dyn Fn(&str) -> Option<String> + Send + Sync;

/// The environment and / or a YAML file.  Cheap to clone.
#[derive(Clone, Default)]
pub struct ConfigSource {
    env: Option<Arc<Lookup>>,
    file: Option<Arc<Document>>,
}

impl ConfigSource {
    /// The process environment only — what the `*EnvLoader`s read.
    pub fn env() -> Self {
        Self::default().with_env()
    }

    /// Settings looked up through `get` instead of the process environment
    /// (tests, or a secret store keyed by variable name).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self::default().with_lookup(get)
    }

    /// The YAML file at `path`, without an environment layer.
    #[cfg(feature = "yaml")]
    pub fn yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let name = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Parse {
            key: name.clone(),
            reason: format!("cannot read the configuration file: {e}"),
        })?;
        Self::yaml_named(&text, name)
    }

    /// A YAML document held in memory, without an environment layer.
    #[cfg(feature = "yaml")]
    pub fn yaml_str(text: &str) -> Result<Self, ConfigError> {
        Self::yaml_named(text, "YAML".into())
    }

    #[cfg(feature = "yaml")]
    fn yaml_named(text: &str, name: String) -> Result<Self, ConfigError> {
        let root: Node = serde_saphyr::from_str(text).map_err(|e| ConfigError::Parse {
            key: name.clone(),
            reason: format!("invalid YAML: {e}"),
        })?;
        Ok(Self {
            env: None,
            file: Some(Arc::new(Document::new(name, root)?)),
        })
    }

    /// The YAML file named by `AUTH_CONFIG_FILE` with the process
    /// environment layered on top, or just the environment when the
    /// variable is unset or empty.
    pub fn standard() -> Result<Self, ConfigError> {
        match std::env::var(ENV_CONFIG_FILE) {
            Ok(path) if !path.trim().is_empty() => Self::standard_file(path.trim()),
            _ => Ok(Self::env()),
        }
    }

    #[cfg(feature = "yaml")]
    fn standard_file(path: &str) -> Result<Self, ConfigError> {
        Ok(Self::yaml_file(path)?.with_env())
    }

    #[cfg(not(feature = "yaml"))]
    fn standard_file(_path: &str) -> Result<Self, ConfigError> {
        Err(ConfigError::Parse {
            key: ENV_CONFIG_FILE.into(),
            reason: "z-auth was built without the `yaml` feature".into(),
        })
    }

    /// Layer the process environment over this source.
    pub fn with_env(self) -> Self {
        self.with_lookup(|key| std::env::var(key).ok())
    }

    /// Layer `get` over this source, replacing any environment layer.
    pub fn with_lookup(
        mut self,
        get: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.env = Some(Arc::new(get));
        self
    }

    /// Whether a file layer is present.
    pub fn has_file(&self) -> bool {
        self.file.is_some()
    }

    /// Read one setting: the environment first, then the file.
    pub fn get(&self, key: &Key) -> Option<Setting> {
        self.get_env(key.env).or_else(|| self.get_file(key.path))
    }

    /// The environment layer only.
    pub fn get_env(&self, env: &str) -> Option<Setting> {
        let value = self.env.as_ref()?(env)?;
        Some(Setting {
            value,
            origin: env.into(),
        })
    }

    /// The file layer only.
    pub fn get_file(&self, path: &str) -> Option<Setting> {
        let doc = self.file.as_ref()?;
        let value = doc.leaves.get(path)?.clone();
        Some(Setting {
            value,
            origin: doc.origin(path),
        })
    }

    /// A crate's view of this source.  `name` is the section's dotted path
    /// (`auth`, `mfa.delivery`, …) and `keys` every setting the crate
    /// reads.  Fails when the file has a key under `name` that is not in
    /// `keys` and not under one of the `skip` paths, which belong to
    /// another crate.
    pub fn section<'a>(
        &'a self,
        name: &str,
        keys: &'a [Key],
        skip: &[&str],
    ) -> Result<Section<'a>, ConfigError> {
        if let Some(doc) = &self.file {
            let under = |path: &str, prefix: &str| {
                path.strip_prefix(prefix)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
            };
            for path in doc.leaves.keys().chain(&doc.containers) {
                if !under(path, name) || skip.iter().any(|s| under(path, s)) {
                    continue;
                }
                if path == name && !doc.containers.contains(path) {
                    return Err(ConfigError::Parse {
                        key: doc.origin(path),
                        reason: "expected a mapping of settings".into(),
                    });
                }
                let known = keys.iter().any(|k| k.path == path)
                    || (doc.containers.contains(path) && keys.iter().any(|k| under(k.path, path)));
                if !known {
                    return Err(ConfigError::Parse {
                        key: doc.origin(path),
                        reason: format!("unknown setting in the `{name}` section"),
                    });
                }
            }
        }
        Ok(Section { source: self, keys })
    }
}

impl std::fmt::Debug for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigSource")
            .field("env", &self.env.is_some())
            .field("file", &self.file.as_ref().map(|d| &d.name))
            .finish()
    }
}

/// A crate's settings within a [`ConfigSource`], looked up by environment
/// variable name.
#[derive(Clone, Copy)]
pub struct Section<'a> {
    source: &'a ConfigSource,
    keys: &'a [Key],
}

impl Section<'_> {
    /// The setting for environment variable `env`.  A variable without a
    /// [`Key`] in this section (e.g. a legacy alias) is read from the
    /// environment only.
    pub fn get(&self, env: &str) -> Option<Setting> {
        match self.keys.iter().find(|k| k.env == env) {
            Some(key) => self.source.get(key),
            None => self.source.get_env(env),
        }
    }

    /// Like [`Self::get`], but a blank value counts as unset in each layer,
    /// so a blank variable does not hide the file's value.
    pub fn get_non_blank(&self, env: &str) -> Option<Setting> {
        let present = |v: &Setting| !v.value.trim().is_empty();
        let from_env = self.source.get_env(env).filter(present);
        from_env.or_else(|| {
            let key = self.keys.iter().find(|k| k.env == env)?;
            self.source.get_file(key.path).filter(present)
        })
    }

    /// The underlying source.
    pub fn source(&self) -> &ConfigSource {
        self.source
    }
}

// ── The file layer ───────────────────────────────────────────────────────────

/// A parsed file, flattened to dotted paths.
struct Document {
    name: String,
    /// Leaf path → value (lists comma-joined).  `null` leaves are absent.
    leaves: BTreeMap<String, String>,
    /// Paths of the mappings, so an empty or mistyped mapping is still
    /// checked by [`ConfigSource::section`].
    containers: std::collections::BTreeSet<String>,
}

impl Document {
    #[cfg_attr(not(feature = "yaml"), allow(dead_code))]
    fn new(name: String, root: Node) -> Result<Self, ConfigError> {
        let mut doc = Self {
            name,
            leaves: BTreeMap::new(),
            containers: Default::default(),
        };
        match root {
            Node::Map(map) => doc.flatten("", map)?,
            Node::Null => {}
            _ => {
                return Err(ConfigError::Parse {
                    key: doc.name.clone(),
                    reason: "the document must be a mapping of sections".into(),
                });
            }
        }
        Ok(doc)
    }

    fn flatten(&mut self, prefix: &str, map: BTreeMap<String, Node>) -> Result<(), ConfigError> {
        for (key, node) in map {
            let path = if prefix.is_empty() {
                key
            } else {
                format!("{prefix}.{key}")
            };
            match node {
                Node::Null => {}
                Node::Scalar(v) => {
                    self.leaves.insert(path, v);
                }
                Node::Seq(items) => {
                    let mut values = Vec::with_capacity(items.len());
                    for item in items {
                        match item {
                            Node::Scalar(v) => values.push(v),
                            Node::Null => {}
                            _ => {
                                return Err(ConfigError::Parse {
                                    key: self.origin(&path),
                                    reason: "expected a list of plain values".into(),
                                });
                            }
                        }
                    }
                    self.leaves.insert(path, values.join(","));
                }
                Node::Map(inner) => {
                    self.containers.insert(path.clone());
                    self.flatten(&path, inner)?;
                }
            }
        }
        Ok(())
    }

    fn origin(&self, path: &str) -> String {
        format!("{path} in {}", self.name)
    }
}

/// A YAML node with every scalar kept as text.
#[cfg_attr(not(feature = "yaml"), allow(dead_code))]
enum Node {
    Null,
    Scalar(String),
    Seq(Vec<Node>),
    Map(BTreeMap<String, Node>),
}

#[cfg(feature = "yaml")]
impl<'de> serde::Deserialize<'de> for Node {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NodeVisitor)
    }
}

#[cfg(feature = "yaml")]
struct NodeVisitor;

#[cfg(feature = "yaml")]
impl<'de> serde::de::Visitor<'de> for NodeVisitor {
    type Value = Node;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a YAML value")
    }

    fn visit_unit<E>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }
    fn visit_none<E>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Node, D::Error> {
        serde::Deserialize::deserialize(d)
    }
    fn visit_bool<E>(self, v: bool) -> Result<Node, E> {
        Ok(Node::Scalar(v.to_string()))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Node, E> {
        Ok(Node::Scalar(v.to_string()))
    }
    fn visit_i128<E>(self, v: i128) -> Result<Node, E> {
        Ok(Node::Scalar(v.to_string()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Node, E> {
        Ok(Node::Scalar(v.to_string()))
    }
    fn visit_u128<E>(self, v: u128) -> Result<Node, E> {
        Ok(Node::Scalar(v.to_string()))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Node, E> {
        Ok(Node::Scalar(v.to_string()))
    }
    fn visit_str<E>(self, v: &str) -> Result<Node, E> {
        Ok(Node::Scalar(v.into()))
    }
    fn visit_string<E>(self, v: String) -> Result<Node, E> {
        Ok(Node::Scalar(v))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Node::Seq(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let mut out = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<Node, Node>()? {
            let Node::Scalar(key) = key else {
                return Err(serde::de::Error::custom(
                    "mapping keys must be plain values",
                ));
            };
            if out.insert(key.clone(), value).is_some() {
                return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
            }
        }
        Ok(Node::Map(out))
    }
}

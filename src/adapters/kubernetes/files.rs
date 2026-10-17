//! Pure volume functions for Kubernetes file delivery (design `delivery-transports.md` §6.3,
//! §6.6). Names, paths and modes only: no kubectl, no secret value ever enters or leaves.
//! The public shape is fixed by K4; `KubeDeployment` wires it in K5.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

/// The mode of the projected volume and of every item: 0440 (design §6.3).
pub const FILE_MODE: u32 = 288;
/// The API server's default `projected.defaultMode`, added when omitted (K1, A5).
pub const SERVER_DEFAULT_MODE: u32 = 420;

/// Which kind of immutable object backs one mounted file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Secret,
    ConfigMap,
}

impl ObjectKind {
    /// The projected source's field name in the Deployment.
    fn field(self) -> &'static str {
        match self {
            ObjectKind::Secret => "secret",
            ObjectKind::ConfigMap => "configMap",
        }
    }
}

/// Why a file binding is not the one opv wrote (design §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    MissingItem,
    MountMissing,
    NotReadOnly,
    WrongPath,
    StillEnv,
}

/// One file path's binding, read back from a Deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Bound { object: String, kind: ObjectKind },
    Other(Why),
}

/// What a workload's security context says about reading the 0440 root-owned files (§6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Readable,
    ReadableAsRoot,
    ReadableAsGroupZero,
    Unreadable,
    Unknown,
}

/// The §6.3 projected volume: one immutable source per object, every field explicit.
pub fn volume(product: &str, _dir: &str, items: &[(&str, ObjectKind, &str)]) -> Value {
    let sources: Vec<Value> = items
        .iter()
        .map(|(name, kind, path)| {
            let mut source = Map::new();
            source.insert("name".to_string(), json!(name));
            source.insert("optional".to_string(), json!(false));
            source.insert(
                "items".to_string(),
                json!([{"key": "value", "path": path, "mode": FILE_MODE}]),
            );
            let mut one = Map::new();
            one.insert(kind.field().to_string(), Value::Object(source));
            Value::Object(one)
        })
        .collect();
    json!({
        "name": volume_name(product),
        "projected": {"defaultMode": FILE_MODE, "sources": sources},
    })
}

/// The §6.3 `volumeMount`: read-only, into the target container only, `{product}` rendered.
pub fn mount(product: &str, dir: &str) -> Value {
    json!({
        "name": volume_name(product),
        "mountPath": expected_dir(dir, product),
        "readOnly": true,
    })
}

/// Adds or replaces opv's volume and the mount in the named container only, and removes the
/// listed env entries from that container. An empty `items` removes the product's volume and
/// mount. A volume or mount not named `opv-files-*` is never touched.
pub fn apply_files(
    deployment: &mut Value,
    container: &str,
    product: &str,
    dir: &str,
    items: &[(&str, ObjectKind, &str)],
    env_names_to_remove: &[String],
) {
    let name = volume_name(product);
    let Some(spec) = deployment.pointer_mut("/spec/template/spec") else {
        return;
    };
    let Some(index) = spec
        .get("containers")
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .position(|c| c.get("name").and_then(Value::as_str) == Some(container))
        })
    else {
        return;
    };
    let pointer = format!("/containers/{index}");

    if let Some(env) = spec
        .pointer_mut(&pointer)
        .and_then(|c| c.get_mut("env"))
        .and_then(Value::as_array_mut)
    {
        env.retain(|e| {
            e.get("name")
                .and_then(Value::as_str)
                .is_none_or(|n| !env_names_to_remove.iter().any(|x| x.as_str() == n))
        });
    }

    if items.is_empty() {
        remove_named(spec, "volumes", &name);
        if let Some(c) = spec.pointer_mut(&pointer) {
            remove_named(c, "volumeMounts", &name);
        }
        return;
    }

    set_named(spec, "volumes", volume(product, dir, items), &name);
    if let Some(c) = spec.pointer_mut(&pointer) {
        set_named(c, "volumeMounts", mount(product, dir), &name);
    }
}

/// Reads the file bindings of one product's volume: path → object, or the first `Other` reason.
pub fn read_bindings(
    deployment: &Value,
    container: &str,
    product: &str,
    dir: &str,
) -> BTreeMap<String, Binding> {
    let name = volume_name(product);
    let want = expected_dir(dir, product);
    let mut out = BTreeMap::new();
    let Some(spec) = deployment.pointer("/spec/template/spec") else {
        return out;
    };
    let Some(target) = spec
        .get("containers")
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.get("name").and_then(Value::as_str) == Some(container))
        })
    else {
        return out;
    };
    let structure = structural_why(target, &name, &want);
    let in_env = env_object_names(target);
    let Some(sources) = spec
        .get("volumes")
        .and_then(Value::as_array)
        .and_then(|vs| {
            vs.iter()
                .find(|v| v.get("name").and_then(Value::as_str) == Some(name.as_str()))
        })
        .and_then(|v| v.pointer("/projected/sources"))
        .and_then(Value::as_array)
    else {
        return out;
    };
    for source in sources {
        let (kind, object) = if let Some(secret) = source.get("secret") {
            (ObjectKind::Secret, secret)
        } else if let Some(config_map) = source.get("configMap") {
            (ObjectKind::ConfigMap, config_map)
        } else {
            continue;
        };
        let Some(object_name) = object.get("name").and_then(Value::as_str) else {
            continue;
        };
        for item in object
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(path) = item.get("path").and_then(Value::as_str) else {
                continue;
            };
            let binding = match structure {
                Some(why) => Binding::Other(why),
                None if item.get("key").and_then(Value::as_str) != Some("value") => {
                    Binding::Other(Why::MissingItem)
                }
                None if in_env.contains(object_name) => Binding::Other(Why::StillEnv),
                None => Binding::Bound {
                    object: object_name.to_string(),
                    kind,
                },
            };
            out.insert(path.to_string(), binding);
        }
    }
    out
}

/// Removes opv's `opv-files-*` volumes and their mounts and normalises the server-added
/// `projected.defaultMode: 420`, so two reads of the same Deployment compare equal (A5).
pub fn strip_managed(deployment: &Value) -> Value {
    let mut out = deployment.clone();
    let Some(spec) = out.pointer_mut("/spec/template/spec") else {
        return out;
    };
    remove_managed(spec, "volumes");
    if let Some(containers) = spec.get_mut("containers").and_then(Value::as_array_mut) {
        for c in containers.iter_mut() {
            remove_managed(c, "volumeMounts");
        }
    }
    if let Some(volumes) = spec.get_mut("volumes").and_then(Value::as_array_mut) {
        for v in volumes.iter_mut() {
            normalise_projected_mode(v);
        }
    }
    out
}

/// The §6.6 verdict for the mounted 0440 root-owned files. The container's `runAsUser` and
/// `runAsGroup` override the pod's; an unset effective group is unknown, not unreadable.
pub fn readability(
    pod_spec_security: Option<&Value>,
    container_security: Option<&Value>,
) -> Verdict {
    let field = |security: Option<&Value>, name: &str| -> Option<u64> {
        security.and_then(|s| s.get(name)).and_then(Value::as_u64)
    };
    if field(pod_spec_security, "fsGroup").is_some() {
        return Verdict::Readable;
    }
    let run_as_user =
        field(container_security, "runAsUser").or_else(|| field(pod_spec_security, "runAsUser"));
    let run_as_group =
        field(container_security, "runAsGroup").or_else(|| field(pod_spec_security, "runAsGroup"));
    match run_as_user {
        Some(0) => Verdict::ReadableAsRoot,
        Some(_) => match run_as_group {
            Some(0) => Verdict::ReadableAsGroupZero,
            Some(_) => Verdict::Unreadable,
            None => Verdict::Unknown,
        },
        None => Verdict::Unknown,
    }
}

/// A foreign (not `opv-files-*`) mount in the container at `dir`, above it or below it.
pub fn mount_conflict(deployment: &Value, container: &str, dir: &str) -> Option<(String, String)> {
    let target = deployment
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.get("name").and_then(Value::as_str) == Some(container))
        })?;
    for mount in target
        .get("volumeMounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = mount.get("name").and_then(Value::as_str) else {
            continue;
        };
        if is_opv_files(Some(name)) {
            continue;
        }
        let Some(path) = mount.get("mountPath").and_then(Value::as_str) else {
            continue;
        };
        if overlaps(dir, path) {
            return Some((name.to_string(), path.to_string()));
        }
    }
    None
}

fn rendered(product: &str) -> String {
    product.replace('_', "-")
}

fn volume_name(product: &str) -> String {
    format!("opv-files-{}", rendered(product))
}

fn expected_dir(dir: &str, product: &str) -> String {
    dir.replace("{product}", &rendered(product))
}

fn is_opv_files(name: Option<&str>) -> bool {
    name.is_some_and(|n| n.starts_with("opv-files-"))
}

fn set_named(owner: &mut Value, key: &str, item: Value, name: &str) {
    let wanted = Value::String(name.to_string());
    if let Some(list) = owner.get_mut(key).and_then(Value::as_array_mut) {
        if let Some(slot) = list.iter_mut().find(|e| e.get("name") == Some(&wanted)) {
            *slot = item;
        } else {
            list.push(item);
        }
        return;
    }
    owner[key] = Value::Array(vec![item]);
}

fn remove_named(owner: &mut Value, key: &str, name: &str) {
    let mut empty = false;
    if let Some(list) = owner.get_mut(key).and_then(Value::as_array_mut) {
        list.retain(|e| e.get("name").and_then(Value::as_str) != Some(name));
        empty = list.is_empty();
    }
    if empty && let Value::Object(map) = owner {
        map.remove(key);
    }
}

fn remove_managed(owner: &mut Value, key: &str) {
    let mut empty = false;
    if let Some(list) = owner.get_mut(key).and_then(Value::as_array_mut) {
        list.retain(|e| !is_opv_files(e.get("name").and_then(Value::as_str)));
        empty = list.is_empty();
    }
    if empty && let Value::Object(map) = owner {
        map.remove(key);
    }
}

fn normalise_projected_mode(volume: &mut Value) {
    if let Some(projected) = volume.get_mut("projected").and_then(Value::as_object_mut)
        && projected.get("defaultMode").and_then(Value::as_u64) == Some(SERVER_DEFAULT_MODE as u64)
    {
        projected.remove("defaultMode");
    }
}

fn structural_why(container: &Value, name: &str, want: &str) -> Option<Why> {
    let mount = container
        .get("volumeMounts")
        .and_then(Value::as_array)
        .and_then(|ms| {
            ms.iter()
                .find(|m| m.get("name").and_then(Value::as_str) == Some(name))
        });
    match mount {
        None => Some(Why::MountMissing),
        Some(m) if m.get("readOnly").and_then(Value::as_bool) != Some(true) => {
            Some(Why::NotReadOnly)
        }
        Some(m) if m.get("mountPath").and_then(Value::as_str) != Some(want) => Some(Why::WrongPath),
        Some(_) => None,
    }
}

fn env_object_names(container: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for entry in container
        .get("env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for pointer in [
            "/valueFrom/secretKeyRef/name",
            "/valueFrom/configMapKeyRef/name",
        ] {
            if let Some(name) = entry.pointer(pointer).and_then(Value::as_str) {
                names.insert(name.to_string());
            }
        }
    }
    names
}

fn overlaps(dir: &str, path: &str) -> bool {
    dir == path
        || dir
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'))
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod files_tests;

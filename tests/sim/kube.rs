//! The simulated `kubectl`: a cluster per context, kept as Kubernetes JSON objects. Failure
//! replies come from `tests/fixtures/kubernetes/failures/`, success replies from
//! `tests/fixtures/kubernetes/success/` (both kubectl v1.36.1, API server v1.37.0, kind
//! v0.33.0); recorded names (`opv-rec`, `opv-norbac`, `api`, `opv-missing` …) are replaced by
//! the call's own.
//!
//! Recorded success replies: `auth can-i` `yes` (success 01) and `no` (failures 02),
//! `apply -o name` (success 02: `secret/<name>`), `delete … --ignore-not-found` (success 03:
//! one `secret "<name>" deleted from <ns> namespace` line per deleted object, nothing for a
//! missing one), `version` and `config get-contexts` (failures 04, 07).
//!
//! The ConfigMap store (K-R7, `tests/fixtures/kubernetes/README.md`): `auth can-i <verb>
//! configmaps` `yes` (success 04) and `no` (failures 08, and 10 for `patch`), `apply -o name`
//! (success 05: `configmap/<name>`), `delete configmap …` (success 17), a 403 on each verb
//! (failures 08; `create` from failures 10) and a missing ConfigMap (failures 09).
//!
//! The Deployment `replace` (K-R1, K-R3): the API server stores the volume, env and mounts
//! exactly as sent and adds only `projected.defaultMode: 420` when it is omitted (success
//! 08–11); `-o jsonpath={.metadata.generation}` prints the bare number (success 08). A
//! replace that puts two mounts at one path in a container is refused with the 422 of
//! K-R2 (failures 12-invalid-replace-mountpath-duplicate), and nothing is stored.
//!
//! The rollout is the world's own: a stored template that changed starts a new revision
//! with its own ReplicaSet. When every source of every projected volume exists, the
//! Deployment reads back rolled out at once. When one is missing (K-R4), the API server
//! still accepts the replace (success 13), the new pod waits in `ContainerCreating` (failures
//! 14, the `get pods` reply opv's rollout wait reads), and the Deployment stays at one new
//! replica of two. The progress deadline is not modelled: K1 did not record a rollout that
//! reached it.
//!
//! Inferred, not recorded: `-o name` and `delete` of kinds other than Secret and ConfigMap
//! reuse the Secret recordings with the kind's `<resource>.<group>` word; `-o json` and
//! `-o jsonpath=…` render the world's own objects (the scenario's documents) rather than a
//! recording.
//!
//! ```json
//! "kubernetes": {
//!   "current_context": "kind-x",
//!   "contexts": {"kind-x": {
//!     "unauthorized": false,                 // 401 on every call
//!     "unreachable": false,                  // connection refused on every call
//!     "user": "system:serviceaccount:ns:opv",
//!     "denied": ["create secrets", "update deployments"],   // RBAC refusals: "<verb> <resource>"
//!     "external_secrets": false,             // the External Secrets Operator is installed
//!     "namespaces": {"ns": {"secrets": [], "deployments": [], "replicasets": [], "pods": []}}}}
//! }
//! ```

use serde_json::{Value, json};

use crate::args::{flag, has, words};
use crate::faults::Kind;
use crate::jsonpath;
use crate::recordings::{Reply, recorded};
use crate::world::World;

const BOOLEAN: &[&str] = &[
    "--server-side",
    "--ignore-not-found",
    "--client",
    "--show-labels",
    "--all",
    "--overwrite",
];
const DIR: &str = "kubernetes/failures";
const OK: &str = "kubernetes/success";
/// The Secret name and namespace in the success recordings.
const RECORDED_SECRET: &str = "opv-api--db-url-abcdefghij";
const RECORDED_NS: &str = "opv-rec";
/// The ConfigMap of success 05 (`apply -o name`) and the first of success 17 (`delete`).
const RECORDED_CONFIGMAP: &str = "opv-api--otel-resource-abcdefghij";
const RECORDED_CONFIGMAP_DELETED: &str = "opv-api--otel-resource-klmnopqrst";
const RECORDED_USER: &str = "system:serviceaccount:opv-rec:opv-norbac";

pub fn call_words(args: &[String]) -> Vec<String> {
    words(args, BOOLEAN)
}

/// `(plural resource, API group suffix, singular for `-o name`)` of a kubectl kind word.
fn resource(word: &str) -> (String, &'static str, String) {
    let base = word.split('.').next().unwrap_or(word).to_lowercase();
    let plural = if base.ends_with('s') {
        base.clone()
    } else {
        format!("{base}s")
    };
    let (group, singular) = match plural.as_str() {
        "deployments" | "replicasets" => (".apps", format!("{}.apps", &plural[..plural.len() - 1])),
        "externalsecrets" | "clustersecretstores" => (
            ".external-secrets.io",
            format!("{}.external-secrets.io", &plural[..plural.len() - 1]),
        ),
        _ => ("", plural[..plural.len() - 1].to_string()),
    };
    (plural, group, singular)
}

struct Target {
    ctx: String,
    ns: String,
    user: String,
}

fn target(world: &World, args: &[String]) -> Target {
    let ctx = flag(args, "--context")
        .map(str::to_string)
        .or_else(|| {
            world.doc["kubernetes"]["current_context"]
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_default();
    let ns = flag(args, "--namespace")
        .or_else(|| flag(args, "-n"))
        .unwrap_or("default")
        .to_string();
    let user = world.doc["kubernetes"]["contexts"][&ctx]["user"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("system:serviceaccount:{ns}:opv"));
    Target { ctx, ns, user }
}

fn case(c: &str, subs: &[(&str, String)]) -> Reply {
    recorded(&format!("{DIR}/{c}"), subs)
}

/// The recorded 403 for `verb` on `res` named `name`.
fn forbidden(t: &Target, verb: &str, res: &str, name: &str) -> Reply {
    if res == "configmaps" {
        return forbidden_configmap(t, verb, name);
    }
    let (c, recorded_name) = match (verb, res) {
        ("get", "secrets") => ("02-forbidden-get-secret", "\"opv-present\""),
        ("list", "secrets") => ("02-forbidden-list-secrets", ""),
        ("patch", "secrets") => (
            "02-forbidden-create-secret",
            "\"opv-api--db-url-abcdefghij\"",
        ),
        ("create", "secrets") => ("02-forbidden-create-secret-clientside", ""),
        ("get", "deployments") => ("02-forbidden-get-deployment", "\"api\""),
        ("update", "deployments") => ("02-forbidden-replace-deployment", "\"api\""),
        _ => return Reply::no_recording(&format!("forbidden on kubectl {verb} {res}"), DIR),
    };
    let mut subs = vec![
        (RECORDED_USER, t.user.clone()),
        (
            "the namespace \"opv-rec\"",
            format!("the namespace \"{}\"", t.ns),
        ),
    ];
    if !recorded_name.is_empty() {
        subs.push((recorded_name, format!("\"{name}\"")));
    }
    case(c, &subs)
}

/// The recorded 403 for `verb` on ConfigMaps (K-R7: failures 08 as an identity without
/// configmap rights, 10 as one without `create`).
fn forbidden_configmap(t: &Target, verb: &str, name: &str) -> Reply {
    let (c, user, recorded_name) = match verb {
        "patch" => (
            "08-forbidden-apply-configmap",
            "opv-noconfigmaps",
            "opv-api--log-level-klmnopqrst",
        ),
        "get" => (
            "08-forbidden-get-configmap",
            "opv-noconfigmaps",
            "opv-api--log-level-abcdefghij",
        ),
        "list" => ("08-forbidden-list-configmaps", "opv-noconfigmaps", ""),
        "delete" => (
            "08-forbidden-delete-configmap",
            "opv-noconfigmaps",
            "opv-api--log-level-abcdefghij",
        ),
        "create" => (
            "10-forbidden-apply-configmap-patch-rights-only",
            "opv-patchonly",
            "opv-api--log-level-klmnopqrst",
        ),
        _ => return Reply::no_recording(&format!("forbidden on kubectl {verb} configmaps"), DIR),
    };
    let mut subs = vec![
        (
            format!("system:serviceaccount:{RECORDED_NS}:{user}"),
            t.user.clone(),
        ),
        (
            format!("the namespace \"{RECORDED_NS}\""),
            format!("the namespace \"{}\"", t.ns),
        ),
    ];
    if !recorded_name.is_empty() {
        subs.push((format!("\"{recorded_name}\""), format!("\"{name}\"")));
    }
    let subs: Vec<(&str, String)> = subs.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
    case(c, &subs)
}

/// `auth can-i <verb> <res>`: the recorded `yes`, or `no` when the world denies it.
fn can_i(verb: &str, res: &str, denied: bool) -> Reply {
    if res != "configmaps" {
        return if denied {
            case("02-can-i-create-secrets-no", &[])
        } else {
            recorded(&format!("{OK}/01-can-i-create-secrets-yes"), &[])
        };
    }
    match (verb, denied) {
        ("patch", true) => case("10-can-i-patch-configmaps-no-without-patch", &[]),
        ("create" | "get" | "list" | "delete", true) => {
            case(&format!("08-can-i-{verb}-configmaps-no"), &[])
        }
        ("create" | "get" | "list" | "delete", false) => {
            recorded(&format!("{OK}/04-can-i-{verb}-configmaps-yes"), &[])
        }
        // `patch configmaps` granted: the K-R7 Roles answered every granted verb `yes`.
        (_, false) => recorded(&format!("{OK}/04-can-i-create-configmaps-yes"), &[]),
        (_, true) => Reply::no_recording(&format!("kubectl auth can-i {verb} {res} (no)"), DIR),
    }
}

/// The recorded 404 for `res` named `name`.
fn not_found(res: &str, name: &str) -> Reply {
    match res {
        "configmaps" => case(
            "09-notfound-configmap",
            &[("\"opv-missing\"", format!("\"{name}\""))],
        ),
        "secrets" => case(
            "03-notfound-secret",
            &[("\"opv-missing\"", format!("\"{name}\""))],
        ),
        "deployments" => case(
            "03-notfound-deployment",
            &[("\"opv-missing\"", format!("\"{name}\""))],
        ),
        _ => Reply::no_recording(&format!("not_found on kubectl get {res}"), DIR),
    }
}

fn is_version(w: &[String]) -> bool {
    w.first().is_some_and(|s| s == "version")
}

pub fn fault(kind: Kind, world: &World, args: &[String]) -> Reply {
    let w = call_words(args);
    let t = target(world, args);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    match kind {
        Kind::SignedOut if is_version(&w) => case("01-unauthorized-version-probe", &[]),
        Kind::SignedOut => case("01-unauthorized-get-secret-list", &[]),
        Kind::Unreachable if is_version(&w) => case("05-unreachable-version-probe", &[]),
        Kind::Unreachable if ws.starts_with(&["auth", "can-i"]) => {
            case("05-unreachable-auth-can-i", &[])
        }
        Kind::Unreachable => case("05-unreachable-get-deployment", &[]),
        Kind::Forbidden => match ws.as_slice() {
            ["get", kind, name] => forbidden(&t, "get", &resource(kind).0, name),
            ["get", kind] => forbidden(&t, "list", &resource(kind).0, ""),
            ["apply"] => forbidden(&t, "patch", "secrets", &manifest_name()),
            ["replace"] => forbidden(&t, "update", "deployments", &manifest_name()),
            _ => missing(kind, &w),
        },
        Kind::NotFound => match ws.as_slice() {
            ["get", kind, name] => not_found(&resource(kind).0, name),
            _ => missing(kind, &w),
        },
        _ => missing(kind, &w),
    }
}

fn missing(kind: Kind, w: &[String]) -> Reply {
    Reply::no_recording(&format!("{} on kubectl {}", kind.name(), w.join(" ")), DIR)
}

/// The name in the manifest on stdin, for a fault reply (the stdin is read once).
fn manifest_name() -> String {
    stdin_doc()
        .and_then(|d| d["metadata"]["name"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn stdin_doc() -> Option<Value> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

pub fn run(world: &mut World, args: &[String]) -> Reply {
    let w = call_words(args);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    if ws == ["version"] && has(args, "--client") {
        return case("07-version-client", &[]);
    }
    if let ["config", "get-contexts", ctx] = ws.as_slice() {
        return if world.doc["kubernetes"]["contexts"].get(*ctx).is_some() {
            case(
                "04-context-present-probe",
                &[("kind-opv-rec", ctx.to_string())],
            )
        } else {
            case(
                "04-context-missing-probe",
                &[("opv-nonexistent", ctx.to_string())],
            )
        };
    }
    let t = target(world, args);
    let Some(cluster) = world.doc["kubernetes"]["contexts"].get(&t.ctx).cloned() else {
        return case(
            "04-context-missing-get-deployment",
            &[("\"opv-nonexistent\"", format!("\"{}\"", t.ctx))],
        );
    };
    if cluster["unauthorized"].as_bool().unwrap_or(false) {
        return fault(Kind::SignedOut, world, args);
    }
    if cluster["unreachable"].as_bool().unwrap_or(false) {
        return fault(Kind::Unreachable, world, args);
    }
    if ws == ["version"] {
        return case("07-version-server", &[]);
    }
    let eso = cluster["external_secrets"].as_bool().unwrap_or(false);
    let denied = |verb: &str, res: &str| {
        cluster["denied"].as_array().is_some_and(|d| {
            d.iter()
                .any(|x| x.as_str() == Some(&format!("{verb} {res}")))
        })
    };
    if ws == ["api-resources"] && !eso {
        return case("06-eso-api-resources", &[]);
    }
    // `get --raw <path>` leaves no positional word after `get`.
    if let Some(raw) = flag(args, "--raw") {
        if !eso && raw.starts_with("/apis/external-secrets.io") {
            let c = if raw.trim_end_matches('/') == "/apis/external-secrets.io" {
                "06-eso-raw-group"
            } else {
                "06-eso-raw-v1"
            };
            return case(c, &[]);
        }
        return Reply::unsupported("kubectl", args);
    }
    if let Some(kind) = ws.get(1).filter(|_| matches!(ws[0], "get" | "delete")) {
        let (res, _, _) = resource(kind);
        if !eso && matches!(res.as_str(), "clustersecretstores" | "externalsecrets") {
            return case(
                "06-eso-get-clustersecretstores",
                &[("\"clustersecretstores\"", format!("\"{res}\""))],
            );
        }
    }
    if cluster["namespaces"].get(&t.ns).is_none() && ws.first() != Some(&"auth") {
        let c = if matches!(ws.first(), Some(&"get")) {
            "03-notfound-namespace-get-deployment"
        } else {
            "03-notfound-namespace-create-secret"
        };
        return case(c, &[("\"opv-missing-ns\"", format!("\"{}\"", t.ns))]);
    }
    let base = format!(
        "/kubernetes/contexts/{}/namespaces/{}",
        esc(&t.ctx),
        esc(&t.ns)
    );
    match ws.as_slice() {
        ["auth", "can-i", verb, res] => {
            let res = resource(res).0;
            can_i(verb, &res, denied(verb, &res))
        }
        ["get", kind, rest @ ..] => {
            let (res, _, singular) = resource(kind);
            let all = objects(world, &base, &res);
            match rest {
                [name] => {
                    if denied("get", &res) {
                        return forbidden(&t, "get", &res, name);
                    }
                    match all.iter().find(|o| o["metadata"]["name"] == *name) {
                        Some(o) => output(args, std::slice::from_ref(o), &singular, false),
                        // 03-notfound-secret-ignore: exit 0, nothing printed.
                        None if has(args, "--ignore-not-found") => {
                            case("03-notfound-secret-ignore", &[])
                        }
                        None => not_found(&res, name),
                    }
                }
                [] => {
                    if denied("list", &res) {
                        return forbidden(&t, "list", &res, "");
                    }
                    let sel = flag(args, "-l").or_else(|| flag(args, "--selector"));
                    if res == "pods"
                        && let Some(stuck) = stuck_pods(world, &base, sel)
                    {
                        return stuck;
                    }
                    let picked: Vec<Value> = all.into_iter().filter(|o| selects(sel, o)).collect();
                    output(args, &picked, &singular, true)
                }
                _ => Reply::unsupported("kubectl", args),
            }
        }
        ["apply"] | ["create"] | ["replace"] => {
            let verb = ws[0];
            let Some(mut doc) = stdin_doc() else {
                return Reply::no_recording(
                    &format!("kubectl {verb} of a manifest it cannot parse"),
                    DIR,
                );
            };
            let (res, _, singular) = resource(doc["kind"].as_str().unwrap_or(""));
            let name = doc["metadata"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let rbac = match verb {
                "apply" => "patch",
                "replace" => "update",
                _ => "create",
            };
            if denied(rbac, &res) {
                return forbidden(&t, rbac, &res, &name);
            }
            if verb == "replace" && res == "deployments" {
                if let Some(refused) = invalid_deployment(&doc) {
                    return refused;
                }
                rollout(world, &base, &mut doc);
            }
            let list = world.array_at(&format!("{base}/{res}"));
            let at = list
                .iter()
                .position(|o| o["metadata"]["name"] == name.as_str());
            let generation = at
                .and_then(|i| list[i]["metadata"]["generation"].as_u64())
                .unwrap_or(0)
                + 1;
            doc["metadata"]["namespace"] = json!(t.ns);
            doc["metadata"]["generation"] = json!(generation);
            doc["metadata"]["resourceVersion"] = json!(generation.to_string());
            match (verb, at) {
                ("replace", None) => {
                    return Reply::no_recording(
                        &format!("kubectl replace of a missing {res}"),
                        DIR,
                    );
                }
                ("create", Some(_)) => {
                    return Reply::no_recording(
                        &format!("kubectl create of an existing {res}"),
                        DIR,
                    );
                }
                (_, Some(i)) => list[i] = doc.clone(),
                (_, None) => list.push(doc.clone()),
            }
            output(args, &[doc], &singular, false)
        }
        ["delete", kind, names @ ..] => {
            let (res, _, _) = resource(kind);
            if denied("delete", &res) {
                return forbidden(&t, "delete", &res, names.first().copied().unwrap_or(""));
            }
            let (_, _, singular) = resource(kind);
            let list = world.array_at(&format!("{base}/{res}"));
            let gone: Vec<&str> = names
                .iter()
                .copied()
                .filter(|n| list.iter().any(|o| o["metadata"]["name"] == *n))
                .collect();
            list.retain(|o| !gone.iter().any(|n| o["metadata"]["name"] == *n));
            if gone.len() != names.len() && !has(args, "--ignore-not-found") {
                return Reply::no_recording(&format!("kubectl delete of a missing {res}"), DIR);
            }
            deleted(&singular, &gone, &t.ns)
        }
        ["patch", "deployment", name, ..] if denied("get", "deployments") => {
            forbidden(&t, "get", "deployments", name)
        }
        _ => Reply::unsupported("kubectl", args),
    }
}

/// K-R2: the API server's 422 for a Deployment whose container mounts two volumes at one
/// path (failures 12-invalid-replace-mountpath-duplicate), the recorded Deployment, container
/// and mount positions and path replaced by the call's own. `None` when nothing is invalid.
fn invalid_deployment(doc: &Value) -> Option<Reply> {
    let containers = doc
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)?;
    for (ci, c) in containers.iter().enumerate() {
        let mut seen = std::collections::BTreeSet::new();
        for (mi, m) in c["volumeMounts"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let Some(path) = m["mountPath"].as_str() else {
                continue;
            };
            if !seen.insert(path) {
                let name = doc["metadata"]["name"].as_str().unwrap_or_default();
                return Some(case(
                    "12-invalid-replace-mountpath-duplicate",
                    &[
                        ("\"api\"", format!("\"{name}\"")),
                        ("containers[0]", format!("containers[{ci}]")),
                        ("volumeMounts[1]", format!("volumeMounts[{mi}]")),
                        ("\"/run/secrets/api\"", format!("\"{path}\"")),
                    ],
                ));
            }
        }
    }
    None
}

/// The objects every projected volume of `deployment`'s pod template names that the
/// namespace at `base` does not hold, as `(kind word, name)`.
fn missing_sources(world: &World, base: &str, deployment: &Value) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for v in deployment
        .pointer("/spec/template/spec/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for s in v
            .pointer("/projected/sources")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for (field, res, word) in [
                ("secret", "secrets", "secret"),
                ("configMap", "configmaps", "configmap"),
            ] {
                let Some(name) = s[field]["name"].as_str() else {
                    continue;
                };
                if s[field]["optional"].as_bool() == Some(true) {
                    continue;
                }
                if !objects(world, base, res)
                    .iter()
                    .any(|o| o["metadata"]["name"] == name)
                {
                    out.push((word, name.to_string()));
                }
            }
        }
    }
    out
}

/// A stable ReplicaSet name for a pod template: `<deployment>-<10 characters>`.
fn replicaset_name(deployment: &str, template: &Value) -> String {
    use sha2::{Digest, Sha256};
    const ALPHABET: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    let digest = Sha256::digest(template.to_string().as_bytes());
    let hash: String = digest
        .iter()
        .take(10)
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    format!("{deployment}-{hash}")
}

/// The world's rollout of a replaced Deployment `doc` (module docs): the API server's
/// one default (K-R3), a new revision and ReplicaSet when the template changed, and a
/// status that is rolled out, or one new replica waiting when a source is missing (K-R4).
fn rollout(world: &mut World, base: &str, doc: &mut Value) {
    for v in doc
        .pointer_mut("/spec/template/spec/volumes")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        if let Some(p) = v.get_mut("projected").and_then(Value::as_object_mut) {
            p.entry("defaultMode").or_insert(json!(420));
        }
    }
    let name = doc["metadata"]["name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let before = objects(world, base, "deployments")
        .into_iter()
        .find(|o| o["metadata"]["name"] == name.as_str())
        .unwrap_or_default();
    let revision = |d: &Value| {
        d.pointer("/metadata/annotations/deployment.kubernetes.io~1revision")
            .and_then(Value::as_str)
            .and_then(|r| r.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let template = doc["spec"]["template"].clone();
    let rs = replicaset_name(&name, &template);
    let mut current = revision(&before);
    if before["spec"]["template"] != template {
        let sets = world.array_at(&format!("{base}/replicasets"));
        let highest = sets.iter().map(revision).max().unwrap_or(0).max(current);
        current = highest + 1;
        sets.retain(|s| s["metadata"]["name"] != rs.as_str());
        sets.push(json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": rs,
                "labels": template["metadata"]["labels"],
                "annotations": {"deployment.kubernetes.io/revision": current.to_string()},
                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment",
                    "name": name, "controller": true}],
            },
            "spec": {"replicas": doc["spec"]["replicas"], "template": template},
        }));
    }
    doc["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
        json!(current.to_string());
    let generation = before["metadata"]["generation"].as_u64().unwrap_or(0) + 1;
    let replicas = doc["spec"]["replicas"].as_u64().unwrap_or(1);
    doc["status"] = if missing_sources(world, base, doc).is_empty() {
        json!({
            "observedGeneration": generation,
            "replicas": replicas,
            "updatedReplicas": replicas,
            "readyReplicas": replicas,
            "availableReplicas": replicas,
        })
    } else {
        json!({
            "observedGeneration": generation,
            "replicas": replicas + 1,
            "updatedReplicas": 1,
            "readyReplicas": replicas,
            "availableReplicas": replicas,
            "unavailableReplicas": 1,
        })
    };
}

/// K-R4: the pods `selector` picks while a Deployment there waits on a missing source — the
/// recorded reply (failures 14) with its ReplicaSet names, pod suffixes and namespace
/// replaced by the world's. `None` when no selected Deployment waits on one.
fn stuck_pods(world: &World, base: &str, selector: Option<&str>) -> Option<Reply> {
    let deployments = objects(world, base, "deployments");
    let d = deployments.iter().find(|d| {
        let labels = json!({"metadata": {"labels": d["spec"]["template"]["metadata"]["labels"]}});
        selects(selector, &labels)
    })?;
    let (kind, _) = missing_sources(world, base, d).into_iter().next()?;
    let name = d["metadata"]["name"].as_str().unwrap_or_default();
    let new = replicaset_name(name, &d["spec"]["template"]);
    let sets = objects(world, base, "replicasets");
    let old = sets
        .iter()
        .filter_map(|s| s["metadata"]["name"].as_str())
        .find(|s| *s != new && s.starts_with(&format!("{name}-")))
        .unwrap_or_default()
        .to_string();
    let (c, recorded_new) = if kind == "configmap" {
        ("14-get-pods-missing-configmap-source-20s", "api-64c8949856")
    } else {
        ("14-get-pods-missing-secret-source-60s", "api-75767cbbb6")
    };
    // A pod name is its ReplicaSet's and a 5-character suffix (the recording's `<POD>`).
    let pod = |rs: &str| {
        format!(
            "{rs}-{}",
            &replicaset_name(rs, &json!(rs))[rs.len() + 1..][..5]
        )
    };
    let recorded_pod = format!("{recorded_new}-<POD>");
    Some(case(
        c,
        &[
            (recorded_pod.as_str(), pod(&new)),
            ("api-7d87cb47bc-<POD>", pod(&old)),
            (recorded_new, new.clone()),
            ("api-7d87cb47bc", old.clone()),
        ],
    ))
}

/// The first stdout line (with its newline) of success recording `case`.
fn success_line(case: &str) -> String {
    let r = recorded(&format!("{OK}/{case}"), &[]);
    let text = String::from_utf8_lossy(&r.stdout);
    text.split_inclusive('\n').next().unwrap_or("").to_string()
}

/// `kubectl delete`'s reply: success 03's line (17's for a ConfigMap) for each object
/// deleted, in the call's order (03-delete-secrets-missing-ignored,
/// 17-delete-configmaps-missing-ignored: nothing for a name that was not there).
fn deleted(singular: &str, gone: &[&str], ns: &str) -> Reply {
    let (line, recorded) = if singular == "configmap" {
        (
            success_line("17-delete-configmaps"),
            format!("configmap \"{RECORDED_CONFIGMAP_DELETED}\""),
        )
    } else {
        (
            success_line("03-delete-secrets"),
            format!("secret \"{RECORDED_SECRET}\""),
        )
    };
    let out: String = gone
        .iter()
        .map(|n| {
            line.replace(&recorded, &format!("{singular} \"{n}\""))
                .replace(
                    &format!(" {RECORDED_NS} namespace"),
                    &format!(" {ns} namespace"),
                )
        })
        .collect();
    Reply::ok(out)
}

/// A JSON-pointer key.
fn esc(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn objects(world: &World, base: &str, res: &str) -> Vec<Value> {
    world
        .doc
        .pointer(&format!("{base}/{res}"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Whether label selector `sel` (`a=b,c`) selects `o`.
fn selects(sel: Option<&str>, o: &Value) -> bool {
    let Some(sel) = sel else { return true };
    let labels = &o["metadata"]["labels"];
    sel.split(',').all(|term| match term.split_once('=') {
        Some((k, v)) => labels[k.trim_end_matches('=')].as_str() == Some(v),
        None => labels.get(term).is_some(),
    })
}

/// Print `objs` as `-o` asks: `name`, `json` or `jsonpath=…`.
fn output(args: &[String], objs: &[Value], singular: &str, list: bool) -> Reply {
    let fmt = flag(args, "-o")
        .or_else(|| flag(args, "--output"))
        .unwrap_or("");
    let doc = if list {
        json!({"apiVersion": "v1", "kind": "List", "items": objs})
    } else {
        objs.first().cloned().unwrap_or(Value::Null)
    };
    if fmt == "name" {
        let (line, recorded) = if singular == "configmap" {
            (
                success_line("05-apply-configmap-created"),
                format!("configmap/{RECORDED_CONFIGMAP}"),
            )
        } else {
            (
                success_line("02-apply-secret-created"),
                format!("secret/{RECORDED_SECRET}"),
            )
        };
        let lines: String = objs
            .iter()
            .map(|o| {
                let name = o["metadata"]["name"].as_str().unwrap_or("");
                line.replace(&recorded, &format!("{singular}/{name}"))
            })
            .collect();
        return Reply::ok(lines);
    }
    if fmt == "json" {
        let mut out = serde_json::to_vec_pretty(&doc).unwrap_or_default();
        out.push(b'\n');
        return Reply::ok(out);
    }
    if let Some(t) = fmt.strip_prefix("jsonpath=") {
        return match jsonpath::render(t, &doc) {
            Some(s) => Reply::ok(s),
            None => Reply::no_recording(
                &format!("kubectl -o {fmt} (a template opv-sim cannot read)"),
                DIR,
            ),
        };
    }
    Reply::no_recording(
        &format!("kubectl -o {fmt:?} (no recorded table output)"),
        DIR,
    )
}

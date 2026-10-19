# Validating an application against the opv contract

An opv project declares its keys once, in `secrets.toml`. `opv contract` prints that
declaration as data, so an application can check its own environment at startup
without a runtime dependency on opv or 1Password. The application reads only its
platform's own channels (environment variables and files); it never reads a value
from opv.

The document holds **names and categories only** — a key's `name`, `kind`, `shape`
name and whether it is required in an environment. It never carries a value, a
1Password id or a rule parameter. Only the process that needs a value reads it from
the platform, exactly as it would without opv.

## What opv emits

```sh
opv contract --json > contract.json          # the contract as data, for the whole configuration
opv contract --env prod --json > prod.json   # one environment
opv contract --component api --json          # one component (product)
opv contract --schema                        # the JSON Schema of the same document
opv contract --check contract.json           # CI: fail when a committed copy is stale
opv contract --relaxations                   # keys relaxed against the default branch
```

The same document is the `contract` section of `opv_state`.

A document looks like this:

```json
{
  "components": [
    {
      "name": "api",
      "environments": [
        {
          "name": "prod",
          "keys": [
            { "name": "DATABASE_URL", "kind": "config", "shape": "url", "required": true },
            { "name": "STRIPE_KEY", "kind": "secret", "shape": "stripe_secret", "required": true },
            { "name": "LOCAL_HOOK", "kind": "config", "shape": null, "required": false }
          ]
        }
      ]
    }
  ],
  "contract_digest": "9f2c…"
}
```

- **`name`** is the environment variable the code reads.
- **`kind`** is `secret` or `config`, the category opv uses.
- **`shape`** is the catalog shape name whose rules equal this key's rules, or `null`
  when the key has its own rules. It is a name only: the rule parameters stay in the
  configuration.
- **`required`** is per environment (contract × presence). A key `except`ed in an
  environment is `false` there and is never demanded at boot.
- **`contract_digest`** is the lowercase hex SHA-256 of the canonical JSON of the
  document without the digest.

`opv contract --check contract.json` compares a committed copy with the contract the
configuration produces and fails in CI with `contract_stale` when the copy is stale,
naming the file. `opv contract --schema` emits a JSON Schema (draft 2020-12) that the
emitted document validates against.

## Startup validation

Read the contract for the environment the process is actually running as, keep the
keys marked `required`, and fail at boot when one is missing or does not match its
shape. Because a broken revision fails its health check and rolls back, a missing
required value is caught at deploy time rather than by the first request.

Each example keeps its own small map from **shape name** to a predicate. The shape
name is what opv publishes; the predicate is the application's own knowledge of that
shape. Error messages name the key and the shape only, never the value.

### zod (TypeScript)

```ts
import { z } from "zod";
import contract from "./contract.json" with { type: "json" };

type Key = { name: string; kind: "secret" | "config"; shape: string | null; required: boolean };
type Env = { name: string; keys: Key[] };

// The application knows what each shape means; opv only publishes the shape name.
const shapes: Record<string, (v: string) => boolean> = {
  url: (v) => /^https?:\/\//.test(v),
  stripe_secret: (v) => v.startsWith("sk_"),
};

const env = process.env.OPV_ENV ?? "dev";
const required = (contract.components as { environments: Env[] }[])
  .flatMap((c) => c.environments)
  .filter((e) => e.name === env)
  .flatMap((e) => e.keys)
  .filter((k) => k.required);

const problems = required.flatMap((k) => {
  const value = process.env[k.name];
  if (!value) return [`missing ${k.name}${k.shape ? ` (shape ${k.shape})` : ""}`];
  if (k.shape && shapes[k.shape] && !shapes[k.shape](value)) {
    return [`invalid ${k.name} (shape ${k.shape})`];
  }
  return [];
});

if (problems.length > 0) {
  throw new Error(`environment does not match the opv contract: ${problems.join(", ")}`);
}
```

### pydantic (Python)

```python
import json
import os
from pathlib import Path


def valid_shape(shape: str | None, value: str) -> bool:
    # The application knows what each shape means; opv only publishes the shape name.
    if shape == "url":
        return value.startswith(("http://", "https://"))
    if shape == "stripe_secret":
        return value.startswith("sk_")
    return True


def check(contract_path: Path, env: str) -> None:
    contract = json.loads(contract_path.read_text())
    required = [
        key
        for component in contract["components"]
        for environment in component["environments"]
        if environment["name"] == env
        for key in environment["keys"]
        if key["required"]
    ]

    problems: list[str] = []
    for key in required:
        value = os.environ.get(key["name"])
        if not value:
            shape = f" (shape {key['shape']})" if key["shape"] else ""
            problems.append(f"missing {key['name']}{shape}")
        elif not valid_shape(key["shape"], value):
            problems.append(f"invalid {key['name']} (shape {key['shape']})")

    if problems:
        raise RuntimeError(f"environment does not match the opv contract: {', '.join(problems)}")


check(Path("contract.json"), os.environ.get("OPV_ENV", "dev"))
```

With pydantic models, map each shape name to a field validator and keep the same
error text (key and shape only).

### serde (Rust)

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    components: Vec<Component>,
}

#[derive(Deserialize)]
struct Component {
    environments: Vec<Environment>,
}

#[derive(Deserialize)]
struct Environment {
    name: String,
    keys: Vec<Key>,
}

#[derive(Deserialize)]
struct Key {
    name: String,
    kind: String,
    shape: Option<String>,
    required: bool,
}

fn valid_shape(shape: Option<&str>, value: &str) -> bool {
    // The application knows what each shape means; opv only publishes the shape name.
    match shape {
        Some("url") => value.starts_with("http://") || value.starts_with("https://"),
        Some("stripe_secret") => value.starts_with("sk_"),
        _ => true,
    }
}

fn check(contract: &str, env: &str) -> Result<(), String> {
    let contract: Contract = serde_json::from_str(contract).map_err(|e| e.to_string())?;
    let mut problems = Vec::new();
    for component in &contract.components {
        for environment in component.environments.iter().filter(|e| e.name == env) {
            for key in environment.keys.iter().filter(|k| k.required) {
                let shape = key.shape.as_deref();
                match std::env::var(&key.name) {
                    Ok(value) if !value.is_empty() => {
                        if !valid_shape(shape, &value) {
                            problems.push(format!("invalid {} (shape {})", key.name, shape.unwrap_or("")));
                        }
                    }
                    _ => {
                        let suffix = shape.map(|s| format!(" (shape {s})")).unwrap_or_default();
                        problems.push(format!("missing {}{suffix}", key.name));
                    }
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "environment does not match the opv contract: {}",
            problems.join(", ")
        ))
    }
}

fn main() {
    let contract = std::fs::read_to_string("contract.json").unwrap();
    let env = std::env::var("OPV_ENV").unwrap_or_else(|_| "dev".into());
    if let Err(problem) = check(&contract, &env) {
        eprintln!("{problem}");
        std::process::exit(1);
    }
}
```

### Go (standard library)

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Key struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	Shape    *string `json:"shape"`
	Required bool    `json:"required"`
}

type Environment struct {
	Name string `json:"name"`
	Keys []Key  `json:"keys"`
}

type Component struct {
	Environments []Environment `json:"environments"`
}

type Contract struct {
	Components []Component `json:"components"`
}

// validShape knows what each shape means; opv only publishes the shape name.
func validShape(shape *string, value string) bool {
	if shape == nil {
		return true
	}
	switch *shape {
	case "url":
		return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
	case "stripe_secret":
		return strings.HasPrefix(value, "sk_")
	default:
		return true
	}
}

func check(path, env string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var contract Contract
	if err := json.Unmarshal(raw, &contract); err != nil {
		return err
	}

	var problems []string
	for _, component := range contract.Components {
		for _, environment := range component.Environments {
			if environment.Name != env {
				continue
			}
			for _, key := range environment.Keys {
				if !key.Required {
					continue
				}
				value, present := os.LookupEnv(key.Name)
				if !present || value == "" {
					shape := ""
					if key.Shape != nil {
						shape = fmt.Sprintf(" (shape %s)", *key.Shape)
					}
					problems = append(problems, fmt.Sprintf("missing %s%s", key.Name, shape))
				} else if !validShape(key.Shape, value) {
					problems = append(problems, fmt.Sprintf("invalid %s (shape %s)", key.Name, *key.Shape))
				}
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("environment does not match the opv contract: %s", strings.Join(problems, ", "))
	}
	return nil
}
```

## Keeping the copy fresh

- Commit the emitted `contract.json` (or per-environment copies) next to the
  application.
- Regenerate it whenever the contract changes. `opv contract --check contract.json`
  is the CI gate: a stale copy exits non-zero with `contract_stale` and names the
  file.
- `opv contract --relaxations` lists the keys this working contract relaxes against
  the default branch, feeding the `opv/relaxations` check; a relaxation is visible in
  review rather than silent.

## What this does not do

- It does not make opv or 1Password a runtime dependency.
- It does not validate an undeclared read. A name the code reads but the contract
  does not declare stays a scanner concern (`opv needs --gate`).
- It does not carry rule parameters. The shape name selects the application's own
  predicate; the rules themselves stay in `secrets.toml`.

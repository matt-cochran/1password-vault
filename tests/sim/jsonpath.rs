//! The subset of kubectl's `-o jsonpath=` templates opv uses: `{.a.b}`, `{.a[*]}`,
//! `{.a[0].b}`, `{"\t"}` literals and nested `{range …}{end}`.

use serde_json::Value;

enum Node {
    Text(String),
    Path(String),
    Range(String, Vec<Node>),
}

/// Render `template` (without the `jsonpath=` prefix) against `doc`; `None` when it does
/// not parse.
pub fn render(template: &str, doc: &Value) -> Option<String> {
    let tokens = tokens(template)?;
    let mut at = 0;
    let nodes = parse(&tokens, &mut at)?;
    if at != tokens.len() {
        return None;
    }
    let mut out = String::new();
    emit(&nodes, doc, &mut out);
    Some(out)
}

enum Token {
    Text(String),
    Brace(String),
}

fn tokens(t: &str) -> Option<Vec<Token>> {
    let mut out = Vec::new();
    let mut rest = t;
    while !rest.is_empty() {
        match rest.find('{') {
            Some(0) => {
                // A quoted literal may hold `}`: scan to the matching close.
                let body = &rest[1..];
                let end = if let Some(quoted) = body.strip_prefix('"') {
                    let close = quoted.find('"')? + 1;
                    close + body[close..].find('}')?
                } else {
                    body.find('}')?
                };
                out.push(Token::Brace(body[..end].trim().to_string()));
                rest = &body[end + 1..];
            }
            Some(i) => {
                out.push(Token::Text(rest[..i].to_string()));
                rest = &rest[i..];
            }
            None => {
                out.push(Token::Text(rest.to_string()));
                rest = "";
            }
        }
    }
    Some(out)
}

fn parse(tokens: &[Token], at: &mut usize) -> Option<Vec<Node>> {
    let mut nodes = Vec::new();
    while *at < tokens.len() {
        match &tokens[*at] {
            Token::Text(t) => nodes.push(Node::Text(t.clone())),
            Token::Brace(b) if b == "end" => return Some(nodes),
            Token::Brace(b) => {
                if let Some(path) = b.strip_prefix("range ") {
                    *at += 1;
                    let body = parse(tokens, at)?;
                    if !matches!(tokens.get(*at), Some(Token::Brace(e)) if e == "end") {
                        return None;
                    }
                    nodes.push(Node::Range(path.trim().to_string(), body));
                } else if let Some(lit) = b.strip_prefix('"').and_then(|l| l.strip_suffix('"')) {
                    nodes.push(Node::Text(lit.replace("\\t", "\t").replace("\\n", "\n")));
                } else {
                    nodes.push(Node::Path(b.clone()));
                }
            }
        }
        *at += 1;
    }
    Some(nodes)
}

/// The values `path` selects from `doc`.
fn select(path: &str, doc: &Value) -> Vec<Value> {
    let mut current = vec![doc.clone()];
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        let (key, index) = match seg.split_once('[') {
            Some((k, i)) => (k, Some(i.trim_end_matches(']'))),
            None => (seg, None),
        };
        let mut next = Vec::new();
        for v in current {
            let v = if key.is_empty() {
                v
            } else {
                v.get(key).cloned().unwrap_or(Value::Null)
            };
            match (index, &v) {
                (None, Value::Null) => {}
                (None, _) => next.push(v),
                (Some("*"), Value::Array(a)) => next.extend(a.iter().cloned()),
                (Some(i), Value::Array(a)) => {
                    if let Some(x) = i.parse::<usize>().ok().and_then(|i| a.get(i)) {
                        next.push(x.clone());
                    }
                }
                _ => {}
            }
        }
        current = next;
    }
    current
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn emit(nodes: &[Node], doc: &Value, out: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) => out.push_str(t),
            Node::Path(p) => {
                let vals: Vec<String> = select(p, doc).iter().map(text).collect();
                out.push_str(&vals.join(" "));
            }
            Node::Range(p, body) => {
                let mut items = select(p, doc);
                if items.len() == 1
                    && !p.ends_with("[*]")
                    && let Value::Array(a) = &items[0]
                {
                    items = a.clone();
                }
                for item in &items {
                    emit(body, item, out);
                }
            }
        }
    }
}

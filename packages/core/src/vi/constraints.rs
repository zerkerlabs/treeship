//! The eight registered VI constraint types, checked with the reference
//! checker's semantics (`verification/constraint_checker.py`), so a credential
//! this module accepts is one the reference accepts, and the reverse.
//!
//! `fulfillment` is a JSON object with the L3 values: `payment_amount`
//! (`{currency, amount}`), `payee`, `merchant`, `line_items`
//! (`[{id|sku, quantity}]`). Allowlists in the constraints must already be
//! inlined (see [`super::L2View::inline_refs`]); `{"...": hash}` entries that
//! were not resolved are treated the way the reference treats them.

use serde_json::Value;

use super::mandate::merchant_matches;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckResult {
    pub satisfied: bool,
    pub violations: Vec<String>,
    pub checked: Vec<String>,
    pub skipped: Vec<String>,
}

fn as_int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Number(n)) if n.is_i64() => n.as_i64(),
        Some(Value::Number(n)) if n.is_u64() => n.as_u64().and_then(|u| i64::try_from(u).ok()),
        _ => None,
    }
}

fn is_ref(v: &Value) -> bool {
    v.get("...").is_some()
}

/// Check `constraints` against `fulfillment`. `open_mandate` makes unknown
/// constraint types a violation (an open mandate must bound every power).
pub fn check_constraints(
    constraints: &[Value],
    fulfillment: &Value,
    open_mandate: bool,
) -> CheckResult {
    let mut r = CheckResult {
        satisfied: true,
        ..Default::default()
    };
    let Some(_) = fulfillment.as_object() else {
        r.satisfied = false;
        r.violations.push("fulfillment must be an object".into());
        return r;
    };
    for c in constraints {
        let Some(ctype) = c.get("type").and_then(Value::as_str) else {
            r.satisfied = false;
            r.violations.push("constraint entry missing 'type'".into());
            continue;
        };
        match ctype {
            "mandate.payment.amount_range" => check_amount(c, fulfillment, &mut r),
            "mandate.payment.allowed_payees" => check_allowlist(
                c,
                fulfillment,
                "payee",
                "mandate.payment.allowed_payees",
                &mut r,
            ),
            "mandate.checkout.allowed_merchants" => check_allowlist(
                c,
                fulfillment,
                "merchant",
                "mandate.checkout.allowed_merchants",
                &mut r,
            ),
            "mandate.checkout.line_items" => check_line_items(c, fulfillment, &mut r),
            "mandate.payment.reference" => r.checked.push(ctype.into()),
            "mandate.payment.budget" => check_budget(c, fulfillment, &mut r),
            "mandate.payment.recurrence" => r.checked.push(ctype.into()),
            "mandate.payment.agent_recurrence" => check_agent_recurrence(c, fulfillment, &mut r),
            other => {
                if open_mandate {
                    r.satisfied = false;
                    r.violations
                        .push(format!("Unknown constraint type: {other}"));
                } else {
                    r.skipped.push(other.into());
                }
            }
        }
    }
    r
}

fn check_amount(c: &Value, f: &Value, r: &mut CheckResult) {
    r.checked.push("mandate.payment.amount_range".into());
    let Some(pa) = f.get("payment_amount").filter(|v| v.is_object()) else {
        r.satisfied = false;
        r.violations
            .push("Missing or invalid payment_amount in fulfillment".into());
        return;
    };
    let Some(amount) = as_int(pa.get("amount")) else {
        r.satisfied = false;
        r.violations
            .push("Missing or non-integer amount in fulfillment payment_amount".into());
        return;
    };
    let currency = c.get("currency").and_then(Value::as_str).unwrap_or("USD");
    if let Some(min) = c.get("min") {
        match as_int(Some(min)) {
            Some(m) if amount < m => {
                r.satisfied = false;
                r.violations
                    .push(format!("Amount below minimum: {amount} < {m} {currency}"));
            }
            Some(_) => {}
            None => {
                r.satisfied = false;
                r.violations
                    .push("Constraint min must be an integer".into());
                return;
            }
        }
    }
    if let Some(max) = c.get("max") {
        match as_int(Some(max)) {
            Some(m) if amount > m => {
                r.satisfied = false;
                r.violations
                    .push(format!("Amount exceeds maximum: {amount} > {m} {currency}"));
            }
            Some(_) => {}
            None => {
                r.satisfied = false;
                r.violations
                    .push("Constraint max must be an integer".into());
                return;
            }
        }
    }
    let fc = pa
        .get("currency")
        .and_then(Value::as_str)
        .unwrap_or(currency);
    if fc != currency {
        r.satisfied = false;
        r.violations
            .push(format!("Currency mismatch: expected {currency}, got {fc}"));
    }
}

fn check_budget(c: &Value, f: &Value, r: &mut CheckResult) {
    // The cumulative cap is the network's to enforce across transactions;
    // the reference marks it checked without local arithmetic. A single
    // transaction above the cumulative maximum can never fit, and the
    // optional `min` is per transaction, so those two are checked here.
    r.checked.push("mandate.payment.budget".into());
    let amount = f
        .get("payment_amount")
        .and_then(|pa| as_int(pa.get("amount")));
    let currency = c.get("currency").and_then(Value::as_str).unwrap_or("USD");
    if let (Some(amount), Some(max)) = (amount, as_int(c.get("max"))) {
        if amount > max {
            r.satisfied = false;
            r.violations.push(format!(
                "Amount exceeds cumulative budget: {amount} > {max} {currency}"
            ));
        }
    }
    if let (Some(amount), Some(min)) = (amount, as_int(c.get("min"))) {
        if amount < min {
            r.satisfied = false;
            r.violations.push(format!(
                "Amount below budget minimum: {amount} < {min} {currency}"
            ));
        }
    }
}

fn check_agent_recurrence(c: &Value, f: &Value, r: &mut CheckResult) {
    // Occurrence counting is the network's; the date window is checkable
    // here when the fulfillment carries `date` (ISO 8601, YYYY-MM-DD).
    r.checked.push("mandate.payment.agent_recurrence".into());
    let (Some(start), Some(end)) = (
        c.get("start_date").and_then(Value::as_str),
        c.get("end_date").and_then(Value::as_str),
    ) else {
        r.satisfied = false;
        r.violations
            .push("agent_recurrence requires start_date and end_date".into());
        return;
    };
    if let Some(today) = f.get("date").and_then(Value::as_str) {
        if today < start || today > end {
            r.satisfied = false;
            r.violations.push(format!(
                "Date {today} outside agent_recurrence window [{start}, {end}]"
            ));
        }
    }
}

fn check_allowlist(c: &Value, f: &Value, field: &str, name: &str, r: &mut CheckResult) {
    r.checked.push(name.into());
    let Some(target) = f
        .get(field)
        .filter(|v| v.is_object() && !v.as_object().map(|o| o.is_empty()).unwrap_or(true))
    else {
        r.satisfied = false;
        r.violations
            .push(format!("Missing or invalid {field} in fulfillment"));
        return;
    };
    let Some(allowed) = c.get("allowed").and_then(Value::as_array) else {
        r.satisfied = false;
        r.violations
            .push(format!("{name} 'allowed' must be a list"));
        return;
    };
    if allowed.is_empty() {
        r.satisfied = false;
        r.violations.push(format!(
            "{name} constraint missing required 'allowed' field"
        ));
        return;
    }
    let inline: Vec<&Value> = allowed
        .iter()
        .filter(|m| {
            m.is_object() && !is_ref(m) && (m.get("id").is_some() || m.get("name").is_some())
        })
        .collect();
    if inline.is_empty() {
        if allowed.iter().all(is_ref) {
            r.checked
                .push(format!("{name} (skipped: no resolved entries)"));
            return;
        }
        r.satisfied = false;
        r.violations
            .push(format!("{name} constraint present but no entries resolved"));
        return;
    }
    if !inline.iter().any(|m| merchant_matches(m, target)) {
        r.satisfied = false;
        r.violations.push(format!(
            "{} {} (id={}) not in allowed list",
            if field == "payee" {
                "Payee"
            } else {
                "Merchant"
            },
            target.get("name").and_then(Value::as_str).unwrap_or(""),
            target.get("id").and_then(Value::as_str).unwrap_or("")
        ));
    }
}

fn item_key(v: &Value) -> Option<String> {
    v.get("id")
        .and_then(Value::as_str)
        .or_else(|| v.get("sku").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn check_line_items(c: &Value, f: &Value, r: &mut CheckResult) {
    r.checked.push("mandate.checkout.line_items".into());
    let items = c
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        r.satisfied = false;
        r.violations
            .push("line_items constraint must have at least one item entry".into());
        return;
    }
    let mut allowed_ids: Vec<String> = Vec::new();
    let mut id_caps: std::collections::BTreeMap<String, i64> = Default::default();
    let mut has_nonempty = false;
    let mut has_wildcard = false;
    let mut total_cap = 0i64;
    let mut has_cap = false;
    for entry in &items {
        let Some(eo) = entry.as_object() else {
            r.satisfied = false;
            r.violations
                .push("line_items item entry must be an object".into());
            continue;
        };
        let acceptable = eo.get("acceptable_items").and_then(Value::as_array);
        match acceptable {
            Some(a) if !a.is_empty() => has_nonempty = true,
            Some(_) => has_wildcard = true,
            None => {}
        }
        if eo
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .is_none()
        {
            r.satisfied = false;
            r.violations
                .push("line_items item entry missing required 'id' field".into());
            continue;
        }
        if !eo.contains_key("acceptable_items") {
            r.satisfied = false;
            r.violations.push(format!(
                "line_items item '{}' missing required 'acceptable_items' field",
                eo["id"]
            ));
            continue;
        }
        let Some(cap) = as_int(eo.get("quantity")) else {
            r.satisfied = false;
            r.violations
                .push("line_items item quantity must be an integer".into());
            continue;
        };
        if cap <= 0 {
            r.satisfied = false;
            r.violations
                .push("line_items item quantity must be positive".into());
            continue;
        }
        has_cap = true;
        total_cap += cap;
        let Some(acceptable) = acceptable else {
            r.satisfied = false;
            r.violations
                .push("line_items acceptable_items must be an array".into());
            continue;
        };
        let mut ids_here: Vec<String> = Vec::new();
        for ai in acceptable {
            if ai.is_object() && !is_ref(ai) {
                if ai
                    .get("title")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .is_none()
                {
                    r.satisfied = false;
                    r.violations.push(format!(
                        "Item {} in acceptable_items missing required 'title'",
                        ai.get("id").and_then(Value::as_str).unwrap_or("?")
                    ));
                }
                if let Some(k) = item_key(ai) {
                    if !ids_here.contains(&k) {
                        ids_here.push(k.clone());
                    }
                    if !allowed_ids.contains(&k) {
                        allowed_ids.push(k);
                    }
                }
            }
        }
        for k in ids_here {
            *id_caps.entry(k).or_insert(0) += cap;
        }
    }
    if has_nonempty && allowed_ids.is_empty() && !has_wildcard {
        r.satisfied = false;
        r.violations
            .push("line_items constraint present but no item IDs resolved".into());
        return;
    }
    let Some(line_items) = f.get("line_items").and_then(Value::as_array) else {
        r.satisfied = false;
        r.violations.push("line_items must be a list".into());
        return;
    };
    if line_items.is_empty() {
        r.satisfied = false;
        r.violations.push(
            "Empty line_items does not satisfy line_items constraint with required items".into(),
        );
        return;
    }
    let mut total = 0i64;
    let mut qty_by_id: std::collections::BTreeMap<String, i64> = Default::default();
    for li in line_items {
        let Some(k) = item_key(li) else {
            r.satisfied = false;
            r.violations.push("Line item missing 'id' field".into());
            continue;
        };
        let Some(q) = as_int(li.get("quantity").or(Some(&Value::from(0)))) else {
            r.satisfied = false;
            r.violations.push(format!("Invalid quantity for item {k}"));
            continue;
        };
        if q < 0 {
            r.satisfied = false;
            r.violations
                .push(format!("Negative quantity for item {k}: {q}"));
            continue;
        }
        if !allowed_ids.is_empty() && !allowed_ids.contains(&k) && !has_wildcard {
            r.satisfied = false;
            r.violations
                .push(format!("Item {k} not in acceptable items: {allowed_ids:?}"));
        }
        total += q;
        *qty_by_id.entry(k).or_insert(0) += q;
    }
    if has_cap && total > total_cap {
        r.satisfied = false;
        r.violations
            .push(format!("Total quantity {total} exceeds limit {total_cap}"));
    }
    for (k, q) in &qty_by_id {
        if let Some(cap) = id_caps.get(k) {
            if q > cap {
                r.satisfied = false;
                r.violations.push(format!(
                    "Quantity for item {k} exceeds per-item limit {cap}"
                ));
            }
        }
    }
    let mode = c
        .get("match_mode")
        .and_then(Value::as_str)
        .unwrap_or("minimum");
    if mode != "minimum" && mode != "exact" {
        r.satisfied = false;
        r.violations.push(format!(
            "line_items match_mode must be 'minimum' or 'exact', got '{mode}'"
        ));
        return;
    }
    if mode == "exact" {
        let mut missing = Vec::new();
        for entry in &items {
            let Some(acceptable) = entry
                .get("acceptable_items")
                .and_then(Value::as_array)
                .filter(|a| !a.is_empty())
            else {
                continue;
            };
            let ids: Vec<String> = acceptable
                .iter()
                .filter(|ai| ai.is_object() && !is_ref(ai))
                .filter_map(item_key)
                .collect();
            if !ids.is_empty()
                && !ids
                    .iter()
                    .any(|id| qty_by_id.get(id).copied().unwrap_or(0) > 0)
            {
                missing.push(format!(
                    "{}: {ids:?}",
                    entry.get("id").and_then(Value::as_str).unwrap_or("?")
                ));
            }
        }
        if !missing.is_empty() {
            r.satisfied = false;
            r.violations.push(format!(
                "match_mode=exact: fulfillment missing required line item(s): {}",
                missing.join(", ")
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn merchants() -> Value {
        json!([{"id":"m1","name":"Tennis Warehouse","website":"https://tw.example"}])
    }

    #[test]
    fn amount_and_currency() {
        let cs = vec![
            json!({"type":"mandate.payment.amount_range","currency":"USD","min":100,"max":40000}),
        ];
        let ok = check_constraints(
            &cs,
            &json!({"payment_amount":{"currency":"USD","amount":27999}}),
            true,
        );
        assert!(ok.satisfied, "{:?}", ok.violations);
        let over = check_constraints(
            &cs,
            &json!({"payment_amount":{"currency":"USD","amount":40001}}),
            true,
        );
        assert_eq!(
            over.violations,
            vec!["Amount exceeds maximum: 40001 > 40000 USD"]
        );
        let eur = check_constraints(
            &cs,
            &json!({"payment_amount":{"currency":"EUR","amount":500}}),
            true,
        );
        assert!(eur.violations[0].starts_with("Currency mismatch"));
    }

    #[test]
    fn payee_allowlist_matches_by_id_then_name_and_website() {
        let cs = vec![json!({"type":"mandate.payment.allowed_payees","allowed":merchants()})];
        assert!(
            check_constraints(
                &cs,
                &json!({"payee":{"id":"m1","name":"x","website":"y"}}),
                true
            )
            .satisfied
        );
        assert!(
            check_constraints(
                &cs,
                &json!({"payee":{"name":"Tennis Warehouse","website":"https://tw.example"}}),
                true
            )
            .satisfied
        );
        assert!(
            !check_constraints(
                &cs,
                &json!({"payee":{"id":"m2","name":"Other","website":"z"}}),
                true
            )
            .satisfied
        );
        let empty = vec![json!({"type":"mandate.payment.allowed_payees","allowed":[]})];
        assert!(!check_constraints(&empty, &json!({"payee":{"id":"m1"}}), true).satisfied);
    }

    #[test]
    fn line_items_caps_and_membership() {
        let cs = vec![
            json!({"type":"mandate.checkout.line_items","items":[{"id":"li-1","acceptable_items":[{"id":"BAB1","title":"Racket"}],"quantity":1}]}),
        ];
        assert!(
            check_constraints(
                &cs,
                &json!({"line_items":[{"id":"BAB1","quantity":1}]}),
                true
            )
            .satisfied
        );
        let two = check_constraints(
            &cs,
            &json!({"line_items":[{"id":"BAB1","quantity":2}]}),
            true,
        );
        assert!(two.violations.iter().any(|v| v.contains("exceeds")));
        let other = check_constraints(
            &cs,
            &json!({"line_items":[{"id":"ZX-9999","quantity":1}]}),
            true,
        );
        assert!(other
            .violations
            .iter()
            .any(|v| v.contains("not in acceptable items")));
        let exact = vec![
            json!({"type":"mandate.checkout.line_items","match_mode":"exact","items":[{"id":"li-1","acceptable_items":[{"id":"A","title":"a"}],"quantity":1},{"id":"li-2","acceptable_items":[{"id":"B","title":"b"}],"quantity":1}]}),
        ];
        let partial = check_constraints(
            &exact,
            &json!({"line_items":[{"id":"A","quantity":1}]}),
            true,
        );
        assert!(partial
            .violations
            .iter()
            .any(|v| v.contains("match_mode=exact")));
    }

    #[test]
    fn unknown_type_is_a_violation_only_for_open_mandates() {
        let cs = vec![json!({"type":"mandate.payment.custom"})];
        assert!(!check_constraints(&cs, &json!({}), true).satisfied);
        let closed = check_constraints(&cs, &json!({}), false);
        assert!(closed.satisfied && closed.skipped == vec!["mandate.payment.custom"]);
    }
}

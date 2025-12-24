use serde_json::json;
use spiffe_rs::spiffeid::{
    format_path, join_path_segments, match_any, match_id, match_member_of, match_one_of,
    require_format_path, require_from_path, require_from_pathf, require_from_segments,
    require_from_string, require_from_stringf, require_from_uri, require_join_path_segments,
    require_trust_domain_from_string, require_trust_domain_from_uri, trust_domain_from_string,
    trust_domain_from_uri, validate_path, validate_path_segment, Error, SpiffeUrl, TrustDomain, ID,
};
use std::cmp::Ordering;
use std::collections::HashSet;
use url::Url;

fn assert_error_contains(err: Result<(), Error>, contains: &str) {
    let err = err.expect_err("expected error");
    assert!(err.to_string().contains(contains));
}

fn assert_id_equal(id: &ID, expect_td: &TrustDomain, expect_path: &str) {
    assert_eq!(&id.trust_domain(), expect_td, "unexpected trust domain");
    assert_eq!(id.path(), expect_path, "unexpected path");
    assert_eq!(
        id.to_string(),
        format!("{}{}", expect_td.id_string(), expect_path)
    );
    assert_eq!(id.url().to_string(), id.to_string());
}

fn as_set(items: &[&str]) -> HashSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn merge_sets(sets: &[HashSet<String>]) -> HashSet<String> {
    let mut out = HashSet::new();
    for set in sets {
        out.extend(set.iter().cloned());
    }
    out
}

#[test]
fn from_string_validation_matches_go() {
    let td = require_trust_domain_from_string("trustdomain");

    let lower_alpha = as_set(&[
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
        "s", "t", "u", "v", "w", "x", "y", "z",
    ]);
    let upper_alpha = as_set(&[
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R",
        "S", "T", "U", "V", "W", "X", "Y", "Z",
    ]);
    let numbers = as_set(&["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]);
    let special = as_set(&[".", "-", "_"]);

    let td_chars = merge_sets(&[lower_alpha.clone(), numbers.clone(), special.clone()]);
    let path_chars = merge_sets(&[lower_alpha, upper_alpha, numbers, special]);

    let assert_ok = |input: &str, expect_td: &TrustDomain, expect_path: &str| {
        let id = ID::from_string(input).expect("valid spiffe id");
        assert_id_equal(&id, expect_td, expect_path);
        let id = ID::from_stringf(format_args!("{}", input)).expect("valid spiffe id");
        assert_id_equal(&id, expect_td, expect_path);
        let id = require_from_string(input);
        assert_id_equal(&id, expect_td, expect_path);
        let id = require_from_stringf(format_args!("{}", input));
        assert_id_equal(&id, expect_td, expect_path);
    };

    let assert_fail = |input: &str, expect_err: &str| {
        let err = ID::from_string(input).unwrap_err();
        assert!(err.to_string().contains(expect_err));
        let err = ID::from_stringf(format_args!("{}", input)).unwrap_err();
        assert!(err.to_string().contains(expect_err));
        assert!(std::panic::catch_unwind(|| require_from_string(input)).is_err());
        assert!(
            std::panic::catch_unwind(|| require_from_stringf(format_args!("{}", input))).is_err()
        );
    };

    assert_fail("", "cannot be empty");
    assert_ok("spiffe://trustdomain", &td, "");

    for i in 0u16..=255 {
        let c = char::from(i as u8);
        if c == '/' {
            continue;
        }
        let s = c.to_string();
        if td_chars.contains(&s) {
            let td_with_char = require_trust_domain_from_string(&format!("trustdomain{s}"));
            assert_ok(
                &format!("spiffe://trustdomain{s}/path"),
                &td_with_char,
                "/path",
            );
        } else {
            assert_fail(
                &format!("spiffe://trustdomain{s}/path"),
                "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
            );
        }

        if path_chars.contains(&s) {
            assert_ok(
                &format!("spiffe://trustdomain/path{s}"),
                &td,
                &format!("/path{s}"),
            );
        } else {
            assert_fail(
                &format!("spiffe://trustdomain/path{s}"),
                "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
            );
        }
    }

    assert_fail("s", "scheme is missing or invalid");
    assert_fail("spiffe:/", "scheme is missing or invalid");
    assert_fail("Spiffe://", "scheme is missing or invalid");
    assert_fail("spiffe://", "trust domain is missing");
    assert_fail("spiffe:///", "trust domain is missing");
    assert_fail("spiffe://trustdomain/", "path cannot have a trailing slash");
    assert_fail(
        "spiffe://trustdomain//",
        "path cannot contain empty segments",
    );
    assert_fail(
        "spiffe://trustdomain//path",
        "path cannot contain empty segments",
    );
    assert_fail(
        "spiffe://trustdomain/path/",
        "path cannot have a trailing slash",
    );

    assert_fail("spiffe://trustdomain/.", "path cannot contain dot segments");
    assert_fail(
        "spiffe://trustdomain/./path",
        "path cannot contain dot segments",
    );
    assert_fail(
        "spiffe://trustdomain/path/./other",
        "path cannot contain dot segments",
    );
    assert_fail(
        "spiffe://trustdomain/path/..",
        "path cannot contain dot segments",
    );
    assert_fail(
        "spiffe://trustdomain/..",
        "path cannot contain dot segments",
    );
    assert_fail(
        "spiffe://trustdomain/../path",
        "path cannot contain dot segments",
    );
    assert_fail(
        "spiffe://trustdomain/path/../other",
        "path cannot contain dot segments",
    );

    assert_ok("spiffe://trustdomain/.path", &td, "/.path");
    assert_ok("spiffe://trustdomain/..path", &td, "/..path");
    assert_ok("spiffe://trustdomain/...", &td, "/...");

    assert_fail(
        "spiffe://%F0%9F%A4%AF/path",
        "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
    );
    assert_fail(
        "spiffe://trustdomain/%F0%9F%A4%AF",
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
    );
    assert_fail(
        "spiffe://%62%61%64/path",
        "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
    );
    assert_fail(
        "spiffe://trustdomain/%62%61%64",
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
    );
}

#[test]
fn trust_domain_from_string_validation_matches_go() {
    let td = require_trust_domain_from_string("trustdomain");
    let assert_ok = |input: &str, expected: &TrustDomain| {
        let actual = trust_domain_from_string(input).expect("valid trust domain");
        assert_eq!(&actual, expected);
        let actual = require_trust_domain_from_string(input);
        assert_eq!(&actual, expected);
    };
    let assert_fail = |input: &str, expect_err: &str| {
        let err = trust_domain_from_string(input).unwrap_err();
        assert!(err.to_string().contains(expect_err));
        assert!(std::panic::catch_unwind(|| require_trust_domain_from_string(input)).is_err());
    };

    assert_fail("", "trust domain is missing");
    assert_ok("spiffe://trustdomain", &td);
    assert_ok("spiffe://trustdomain/path", &td);
    assert_fail("spiffe:/trustdomain/path", "scheme is missing or invalid");
    assert_fail("spiffe://", "trust domain is missing");
    assert_fail("spiffe:///path", "trust domain is missing");
    assert_fail("spiffe://trustdomain/", "path cannot have a trailing slash");
    assert_fail(
        "spiffe://trustdomain/path/",
        "path cannot have a trailing slash",
    );
    assert_fail(
        "spiffe://%F0%9F%A4%AF/path",
        "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
    );
    assert_fail(
        "spiffe://trustdomain/%F0%9F%A4%AF",
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
    );

    let lower_alpha = as_set(&[
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
        "s", "t", "u", "v", "w", "x", "y", "z",
    ]);
    let numbers = as_set(&["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]);
    let special = as_set(&[".", "-", "_"]);
    let td_chars = merge_sets(&[lower_alpha, numbers, special]);

    for i in 0u16..=255 {
        let c = char::from(i as u8);
        let s = c.to_string();
        if td_chars.contains(&s) {
            let expected = require_trust_domain_from_string(&format!("trustdomain{s}"));
            assert_ok(&format!("trustdomain{s}"), &expected);
            assert_ok(&format!("spiffe://trustdomain{s}"), &expected);
        } else {
            assert_fail(
                &format!("trustdomain{s}"),
                "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
            );
        }
    }
}

#[test]
fn trust_domain_from_uri_matches_go() {
    let parse = |s: &str| Url::parse(s).expect("valid url");
    let assert_ok = |s: &str| {
        let url = parse(s);
        let td = trust_domain_from_uri(&url).expect("valid trust domain");
        assert_eq!(
            td,
            require_trust_domain_from_string(url.host_str().unwrap_or(""))
        );
    };
    let assert_fail = |url: Url, expect_err: &str| {
        let err = trust_domain_from_uri(&url).unwrap_err();
        assert!(err.to_string().contains(expect_err));
    };

    assert_ok("spiffe://trustdomain");
    assert_ok("spiffe://trustdomain/path");
    assert_fail(
        Url::parse("spiffe://").expect("url"),
        "trust domain is missing",
    );
    assert_fail(
        Url::parse("http://trustdomain").expect("url"),
        "scheme is missing or invalid",
    );
    assert_fail(
        parse("spiffe://trust$domain"),
        "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
    );
    assert_fail(
        parse("spiffe://trustdomain/path$"),
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
    );
}

#[test]
fn trust_domain_helpers_match_go() {
    assert!(TrustDomain::default().is_zero());
    let td = require_trust_domain_from_string("trustdomain");
    assert_eq!(td.id().to_string(), "spiffe://trustdomain");
    assert_eq!(td.id_string(), "spiffe://trustdomain");
    assert_eq!(td.compare(&td), Ordering::Equal);
    let b = require_trust_domain_from_string("b");
    let a = require_trust_domain_from_string("a");
    assert_eq!(a.compare(&b), Ordering::Less);
    assert_eq!(b.compare(&a), Ordering::Greater);
}

#[test]
fn trust_domain_text_round_trip() {
    let mut td = TrustDomain::default();
    assert!(td.marshal_text().is_none());
    td = require_trust_domain_from_string("trustdomain");
    assert_eq!(td.marshal_text().unwrap(), b"trustdomain");

    let mut td = TrustDomain::default();
    td.unmarshal_text(b"").expect("empty is ok");
    assert!(td.is_zero());
    assert!(td.unmarshal_text(b"BAD").is_err());
    td.unmarshal_text(b"trustdomain").expect("valid");
    assert_eq!(td.name(), "trustdomain");
}

#[test]
fn trust_domain_json_round_trip() {
    let mut payload = json!({ "trustDomain": "" });
    let td: TrustDomain = serde_json::from_value(payload["trustDomain"].clone()).unwrap();
    assert!(td.is_zero());

    payload["trustDomain"] = json!("trustdomain");
    let td: TrustDomain = serde_json::from_value(payload["trustDomain"].clone()).unwrap();
    assert_eq!(td.name(), "trustdomain");

    let td = TrustDomain::default();
    let serialized = serde_json::to_value(&td).unwrap();
    assert_eq!(serialized, json!(""));
}

#[test]
fn from_uri_matches_go() {
    let parse = |s: &str| Url::parse(s).expect("valid url");
    let assert_ok = |s: &str| {
        let url = parse(s);
        let id = ID::from_uri(&url).expect("valid spiffe id");
        assert_eq!(id.to_string(), s);
    };
    let assert_fail = |url: Url, expect_err: &str| {
        let err = ID::from_uri(&url).unwrap_err();
        assert!(err.to_string().contains(expect_err));
    };

    assert_ok("spiffe://trustdomain");
    assert_ok("spiffe://trustdomain/path");
    assert_fail(
        Url::parse("spiffe://").expect("url"),
        "trust domain is missing",
    );
    assert_fail(
        Url::parse("http://trustdomain").expect("url"),
        "scheme is missing or invalid",
    );
    assert_fail(
        parse("spiffe://trust$domain"),
        "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
    );
    assert_fail(
        parse("spiffe://trustdomain/path$"),
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
    );
}

#[test]
fn from_segments_matches_go() {
    let td = require_trust_domain_from_string("trustdomain");
    let id = ID::from_segments(td.clone(), &[]).expect("valid");
    assert_id_equal(&id, &td, "");
    let id = ID::from_segments(td.clone(), &["foo"]).expect("valid");
    assert_id_equal(&id, &td, "/foo");
    let id = ID::from_segments(td.clone(), &["foo", "bar"]).expect("valid");
    assert_id_equal(&id, &td, "/foo/bar");

    assert!(ID::from_segments(td.clone(), &[""]).is_err());
    assert!(ID::from_segments(td.clone(), &["/"]).is_err());
    assert!(ID::from_segments(td.clone(), &["/foo"]).is_err());
    assert!(ID::from_segments(td, &["$"]).is_err());
}

#[test]
fn from_pathf_matches_go() {
    let td = require_trust_domain_from_string("trustdomain");
    let id = ID::from_pathf(td.clone(), format_args!("/{}", "foo")).expect("valid");
    assert_id_equal(&id, &td, "/foo");
    let id = ID::from_pathf(td.clone(), format_args!("")).expect("valid");
    assert_id_equal(&id, &td, "");
    let err = ID::from_pathf(td.clone(), format_args!("{}", "foo")).unwrap_err();
    assert_eq!(err.to_string(), "path must have a leading slash");
    let err = ID::from_pathf(td, format_args!("/")).unwrap_err();
    assert_eq!(err.to_string(), "path cannot have a trailing slash");
}

#[test]
fn id_methods_match_go() {
    let td = require_trust_domain_from_string("trustdomain");
    let id = require_from_segments(td.clone(), &["path", "element"]);
    assert!(id.member_of(&td));
    let empty = require_from_segments(td.clone(), &[]);
    assert!(empty.member_of(&td));
    let td2 = require_trust_domain_from_string("domain2.test");
    let id2 = require_from_segments(td2, &["path", "element"]);
    assert!(!id2.member_of(&td));

    let id = ID::zero();
    assert!(id.is_zero());
    let id = require_from_string("spiffe://trustdomain");
    assert_eq!(id.to_string(), "spiffe://trustdomain");
    let id = require_from_string("spiffe://trustdomain/path");
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");

    let id = require_from_segments(td.clone(), &["path", "element"]);
    assert_eq!(
        id.url(),
        SpiffeUrl::new("spiffe", "trustdomain", "/path/element")
    );
    let id = require_from_segments(td.clone(), &[]);
    assert_eq!(id.url(), SpiffeUrl::new("spiffe", "trustdomain", ""));
    let id = ID::zero();
    assert_eq!(id.url(), SpiffeUrl::empty());
}

#[test]
fn id_replace_append_matches_go() {
    let td = require_trust_domain_from_string("trustdomain");
    let assert_ok = |start: &str, replace: &str, expect: &str| {
        let id = require_from_path(td.clone(), start)
            .replace_path(replace)
            .expect("replace path");
        assert_id_equal(&id, &td, expect);
    };
    let assert_fail = |start: &str, replace: &str, expect: &str| {
        let err = require_from_path(td.clone(), start)
            .replace_path(replace)
            .unwrap_err();
        assert_eq!(err.to_string(), expect);
    };

    assert_ok("", "/foo", "/foo");
    assert_ok("/path", "/foo", "/foo");
    assert_fail("", "foo", "path must have a leading slash");
    assert_fail("/path", "/", "path cannot have a trailing slash");
    assert_fail("/path", "foo", "path must have a leading slash");
    let err = ID::zero().replace_path("/").unwrap_err();
    assert_eq!(err.to_string(), "cannot replace path on a zero ID value");

    let id = require_from_path(td.clone(), "/path")
        .replace_pathf(format_args!("/{}", "foo"))
        .expect("replace pathf");
    assert_id_equal(&id, &td, "/foo");
    let err = require_from_path(td.clone(), "/path")
        .replace_pathf(format_args!("{}", "foo"))
        .unwrap_err();
    assert_eq!(err.to_string(), "path must have a leading slash");
    let err = ID::zero().replace_pathf(format_args!("/")).unwrap_err();
    assert_eq!(err.to_string(), "cannot replace path on a zero ID value");

    let id = require_from_path(td.clone(), "/path")
        .replace_segments(&["foo"])
        .expect("replace segments");
    assert_id_equal(&id, &td, "/foo");
    let err = require_from_path(td.clone(), "/path")
        .replace_segments(&[""])
        .unwrap_err();
    assert_eq!(err.to_string(), "path cannot contain empty segments");
    let err = ID::zero().replace_segments(&["/"]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cannot replace path segments on a zero ID value"
    );

    let id = require_from_path(td.clone(), "/path")
        .append_path("/foo")
        .expect("append path");
    assert_id_equal(&id, &td, "/path/foo");
    let err = require_from_path(td.clone(), "/path")
        .append_path("foo")
        .unwrap_err();
    assert_eq!(err.to_string(), "path must have a leading slash");
    let err = ID::zero().append_path("/").unwrap_err();
    assert_eq!(err.to_string(), "cannot append path on a zero ID value");

    let id = require_from_path(td.clone(), "/path")
        .append_pathf(format_args!("/{}", "foo"))
        .expect("append pathf");
    assert_id_equal(&id, &td, "/path/foo");
    let err = require_from_path(td.clone(), "/path")
        .append_pathf(format_args!("{}", "foo"))
        .unwrap_err();
    assert_eq!(err.to_string(), "path must have a leading slash");
    let err = ID::zero().append_pathf(format_args!("/")).unwrap_err();
    assert_eq!(err.to_string(), "cannot append path on a zero ID value");

    let id = require_from_path(td.clone(), "/path")
        .append_segments(&["foo"])
        .expect("append segments");
    assert_id_equal(&id, &td, "/path/foo");
    let err = require_from_path(td.clone(), "/path")
        .append_segments(&[""])
        .unwrap_err();
    assert_eq!(err.to_string(), "path cannot contain empty segments");
    let err = ID::zero().append_segments(&["/"]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cannot append path segments on a zero ID value"
    );
}

#[test]
fn matcher_behavior_matches_go() {
    let zero = ID::zero();
    let foo = require_from_string("spiffe://foo.test");
    let foo_a = require_from_string("spiffe://foo.test/A");
    let foo_b = require_from_string("spiffe://foo.test/B");
    let foo_c = require_from_string("spiffe://foo.test/sub/C");
    let bar_a = require_from_string("spiffe://bar.test/A");

    let test_match =
        |matcher: Box<dyn Fn(&ID) -> Result<(), spiffe_rs::spiffeid::MatcherError>>,
         zero_err: &str,
         foo_err: &str,
         foo_a_err: &str,
         foo_b_err: &str,
         foo_c_err: &str,
         bar_a_err: &str| {
            let check = |id: &ID, expect_err: &str| {
                let result = matcher(id);
                if expect_err.is_empty() {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(result.unwrap_err().to_string(), expect_err);
                }
            };
            check(&zero, zero_err);
            check(&foo, foo_err);
            check(&foo_a, foo_a_err);
            check(&foo_b, foo_b_err);
            check(&foo_c, foo_c_err);
            check(&bar_a, bar_a_err);
        };

    test_match(match_any(), "", "", "", "", "", "");
    test_match(
        match_id(foo_a.clone()),
        "unexpected ID \"\"",
        "unexpected ID \"spiffe://foo.test\"",
        "",
        "unexpected ID \"spiffe://foo.test/B\"",
        "unexpected ID \"spiffe://foo.test/sub/C\"",
        "unexpected ID \"spiffe://bar.test/A\"",
    );
    test_match(
        match_id(foo.clone()),
        "unexpected ID \"\"",
        "",
        "unexpected ID \"spiffe://foo.test/A\"",
        "unexpected ID \"spiffe://foo.test/B\"",
        "unexpected ID \"spiffe://foo.test/sub/C\"",
        "unexpected ID \"spiffe://bar.test/A\"",
    );
    test_match(
        match_one_of(&[foo.clone(), foo_b.clone(), foo_c.clone(), bar_a.clone()]),
        "unexpected ID \"\"",
        "",
        "unexpected ID \"spiffe://foo.test/A\"",
        "",
        "",
        "",
    );
    test_match(
        match_one_of(&[]),
        "unexpected ID \"\"",
        "unexpected ID \"spiffe://foo.test\"",
        "unexpected ID \"spiffe://foo.test/A\"",
        "unexpected ID \"spiffe://foo.test/B\"",
        "unexpected ID \"spiffe://foo.test/sub/C\"",
        "unexpected ID \"spiffe://bar.test/A\"",
    );
    test_match(
        match_member_of(foo.trust_domain()),
        "unexpected trust domain \"\"",
        "",
        "",
        "",
        "",
        "unexpected trust domain \"bar.test\"",
    );
    test_match(
        match_member_of(TrustDomain::default()),
        "",
        "unexpected trust domain \"foo.test\"",
        "unexpected trust domain \"foo.test\"",
        "unexpected trust domain \"foo.test\"",
        "unexpected trust domain \"foo.test\"",
        "unexpected trust domain \"bar.test\"",
    );
}

#[test]
fn require_helpers_match_go() {
    let td = require_trust_domain_from_string("trustdomain");
    let id = require_from_path(td.clone(), "/path");
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");
    assert!(std::panic::catch_unwind(|| require_from_path(td.clone(), "relative")).is_err());

    let id = require_from_pathf(td.clone(), format_args!("/{}", "path"));
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");
    assert!(std::panic::catch_unwind(|| require_from_pathf(
        td.clone(),
        format_args!("{}", "relative")
    ))
    .is_err());

    let id = require_from_segments(td.clone(), &["path"]);
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");
    assert!(
        std::panic::catch_unwind(|| require_from_segments(td.clone(), &["/absolute"])).is_err()
    );

    let id = require_from_string("spiffe://trustdomain/path");
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");
    assert!(std::panic::catch_unwind(|| require_from_string("")).is_err());

    let id = require_from_stringf(format_args!("spiffe://trustdomain/{}", "path"));
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");
    assert!(
        std::panic::catch_unwind(|| require_from_stringf(format_args!(
            "{}://trustdomain/path",
            "sparfe"
        )))
        .is_err()
    );

    let id = require_from_uri(&Url::parse("spiffe://trustdomain/path").unwrap());
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");
    assert!(
        std::panic::catch_unwind(|| require_from_uri(&Url::parse("spiffe://").unwrap())).is_err()
    );

    let td = require_trust_domain_from_string("spiffe://trustdomain/path");
    assert_eq!(td.name(), "trustdomain");
    assert!(
        std::panic::catch_unwind(|| require_trust_domain_from_string("spiffe://TRUSTDOMAIN/path"))
            .is_err()
    );

    let td = require_trust_domain_from_uri(&Url::parse("spiffe://trustdomain/path").unwrap());
    assert_eq!(td.name(), "trustdomain");
    assert!(std::panic::catch_unwind(|| require_trust_domain_from_uri(
        &Url::parse("spiffe://").unwrap()
    ))
    .is_err());

    let path = require_format_path(format_args!("/{}", "path"));
    assert_eq!(path, "/path");
    assert!(std::panic::catch_unwind(|| require_format_path(format_args!("{}", "path"))).is_err());

    let path = require_join_path_segments(&["path"]);
    assert_eq!(path, "/path");
    assert!(std::panic::catch_unwind(|| require_join_path_segments(&["/absolute"])).is_err());
}

#[test]
fn path_helpers_match_go() {
    assert!(validate_path("").is_ok());
    assert_error_contains(validate_path("relative"), "path must have a leading slash");
    assert_error_contains(validate_path("/"), "path cannot have a trailing slash");
    assert_error_contains(validate_path("/."), "path cannot contain dot segments");
    assert_error_contains(validate_path("/.."), "path cannot contain dot segments");
    assert!(validate_path("/a/b").is_ok());

    assert_error_contains(
        validate_path_segment(""),
        "path cannot contain empty segments",
    );
    assert_error_contains(
        validate_path_segment("."),
        "path cannot contain dot segments",
    );
    assert_error_contains(
        validate_path_segment(".."),
        "path cannot contain dot segments",
    );
    assert_error_contains(
        validate_path_segment("/"),
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores",
    );
    assert!(validate_path_segment("a").is_ok());

    let path = join_path_segments(&["a", "b"]).expect("join segments");
    assert_eq!(path, "/a/b");
    assert!(join_path_segments(&[""]).is_err());

    let path = format_path(format_args!("/{}", "a")).expect("format path");
    assert_eq!(path, "/a");
    assert!(format_path(format_args!("{}", "a")).is_err());
}

#[test]
fn id_json_round_trip() {
    let id = ID::zero();
    let serialized = serde_json::to_value(&id).unwrap();
    assert_eq!(serialized, json!(""));

    let id: ID = serde_json::from_value(json!("spiffe://trustdomain/path")).unwrap();
    assert_eq!(id.to_string(), "spiffe://trustdomain/path");

    let err = serde_json::from_value::<ID>(json!("BAD")).unwrap_err();
    assert!(err.to_string().contains("scheme is missing or invalid"));
}

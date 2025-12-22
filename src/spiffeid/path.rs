use crate::spiffeid::charset::is_backcompat_path_char;
use crate::spiffeid::{Error, Result};

/// Formats a path component using standard formatting arguments and validates it.
pub fn format_path(args: std::fmt::Arguments<'_>) -> Result<String> {
    let path = format!("{}", args);
    validate_path(&path)?;
    Ok(path)
}

/// Joins multiple path segments into a single path and validates each segment.
pub fn join_path_segments(segments: &[&str]) -> Result<String> {
    let mut out = String::new();
    for segment in segments {
        validate_path_segment(segment)?;
        out.push('/');
        out.push_str(segment);
    }
    Ok(out)
}

/// Validates a SPIFFE ID path component.
///
/// It must start with a forward slash and follow SPIFFE path rules.
pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    if !path.starts_with('/') {
        return Err(Error::NoLeadingSlash);
    }

    let bytes = path.as_bytes();
    let mut segment_start = 0usize;
    for (idx, &c) in bytes.iter().enumerate() {
        if c == b'/' {
            match &path[segment_start..idx] {
                "/" => return Err(Error::EmptySegment),
                "/." | "/.." => return Err(Error::DotSegment),
                _ => {}
            }
            segment_start = idx;
            continue;
        }
        if !is_valid_path_segment_char(c) {
            return Err(Error::BadPathSegmentChar);
        }
    }

    match &path[segment_start..] {
        "/" => Err(Error::TrailingSlash),
        "/." | "/.." => Err(Error::DotSegment),
        _ => Ok(()),
    }
}

/// Validates a single SPIFFE ID path segment.
pub fn validate_path_segment(segment: &str) -> Result<()> {
    match segment {
        "" => return Err(Error::EmptySegment),
        "." | ".." => return Err(Error::DotSegment),
        _ => {}
    }
    for &c in segment.as_bytes() {
        if !is_valid_path_segment_char(c) {
            return Err(Error::BadPathSegmentChar);
        }
    }
    Ok(())
}

fn is_valid_path_segment_char(c: u8) -> bool {
    matches!(c, b'a'..=b'z')
        || matches!(c, b'A'..=b'Z')
        || matches!(c, b'0'..=b'9')
        || matches!(c, b'-' | b'.' | b'_')
        || is_backcompat_path_char(c)
}

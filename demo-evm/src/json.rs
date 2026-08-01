//! Minimal JSON: a value type, a writer (for JSON-RPC requests), and a
//! total, panic-free parser (for responses). No serde — the demo only
//! needs the JSON-RPC shapes: strings, integers, booleans, null,
//! arrays, nested objects.
//!
//! Deliberate limits (RFC 8259 allows all of these restrictions):
//! - numbers are INTEGERS only (fractions/exponents are rejected —
//!   JSON-RPC quantities are hex strings, ids are small ints);
//! - nesting is capped at [`MAX_DEPTH`] levels;
//! - objects preserve insertion order and allow duplicate keys (the
//!   parser is a dumb reader; consumers pick the FIRST match, matching
//!   how every JSON-RPC peer we care about behaves).

/// Maximum nesting depth the parser accepts (arrays + objects).
pub const MAX_DEPTH: usize = 64;

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i128),
    /// Floating-point numbers (only parsed, never emitted — JSON-RPC
    /// requests carry ints/strings; responses carry floats in e.g.
    /// `eth_feeHistory`'s `gasUsedRatio`).
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    /// Insertion-ordered key/value pairs.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Serialize (the writer used for JSON-RPC requests).
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => out.push_str(&i.to_string()),
            Json::Float(f) => out.push_str(&f.to_string()),
            Json::Str(s) => write_str(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    /// First value for `key` in an object, if any.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Json::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

/// JSON string literal with the mandatory escapes (RFC 8259 §7).
fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse failures (the parser is total: every input either parses or
/// returns one of these — no panics, no aborts).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum JsonError {
    #[error("unexpected byte at offset {pos}: {what}")]
    Unexpected { pos: usize, what: &'static str },
    #[error("invalid string escape at offset {0}")]
    BadEscape(usize),
    #[error("invalid \\u escape at offset {0}")]
    BadUnicodeEscape(usize),
    #[error("unpaired surrogate in \\u escape at offset {0}")]
    UnpairedSurrogate(usize),
    #[error("invalid number at offset {0}")]
    BadNumber(usize),
    #[error("invalid literal at offset {0}")]
    BadLiteral(usize),
    #[error("nesting deeper than MAX_DEPTH at offset {0}")]
    DepthLimit(usize),
    #[error("unexpected end of input")]
    Truncated,
    #[error("trailing bytes after the value at offset {0}")]
    Trailing(usize),
}

/// Parse one JSON value; trailing (non-whitespace) input is an error.
pub fn parse(input: &str) -> Result<Json, JsonError> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.pos != p.bytes.len() {
        return Err(JsonError::Trailing(p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        match self.peek() {
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'[') => {
                if self.depth >= MAX_DEPTH {
                    return Err(JsonError::DepthLimit(self.pos));
                }
                self.pos += 1;
                self.depth += 1;
                let items = self.seq(b']')?;
                self.depth -= 1;
                Ok(Json::Array(items))
            }
            Some(b'{') => {
                if self.depth >= MAX_DEPTH {
                    return Err(JsonError::DepthLimit(self.pos));
                }
                self.pos += 1;
                self.depth += 1;
                let pairs = self.object_pairs()?;
                self.depth -= 1;
                Ok(Json::Object(pairs))
            }
            Some(_) => Err(JsonError::Unexpected {
                pos: self.pos,
                what: "not a value",
            }),
            None => Err(JsonError::Truncated),
        }
    }

    fn literal(&mut self, lit: &[u8], value: Json) -> Result<Json, JsonError> {
        if self.bytes.len() - self.pos >= lit.len()
            && &self.bytes[self.pos..self.pos + lit.len()] == lit
        {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(JsonError::BadLiteral(self.pos))
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // RFC 8259 §6: no leading zeros.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(JsonError::BadNumber(start));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(JsonError::BadNumber(start)),
        }
        // Optional fraction and exponent → Float.
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::BadNumber(start));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::BadNumber(start));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| JsonError::BadNumber(start))?;
        if float {
            // A syntactically valid JSON number always parses as f64
            // (overflow yields ±inf, which is fine for a dumb reader).
            text.parse::<f64>()
                .map(Json::Float)
                .map_err(|_| JsonError::BadNumber(start))
        } else {
            text.parse::<i128>()
                .map(Json::Int)
                .map_err(|_| JsonError::BadNumber(start))
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        debug_assert_eq!(self.bump(), Some(b'"'));
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(JsonError::Truncated),
                Some(b'"') => return Ok(out),
                Some(b'\\') => out.push(self.escape()?),
                Some(b) if b < 0x20 => {
                    return Err(JsonError::Unexpected {
                        pos: self.pos - 1,
                        what: "raw control char",
                    })
                }
                Some(b) if b < 0x80 => out.push(b as char),
                Some(b) => {
                    // Multi-byte UTF-8: the input is a &str, so bytes are
                    // valid UTF-8; copy the whole sequence.
                    let len = utf8_len(b);
                    let from = self.pos - 1;
                    if from + len > self.bytes.len() {
                        return Err(JsonError::Truncated);
                    }
                    let s = std::str::from_utf8(&self.bytes[from..from + len]).map_err(|_| {
                        JsonError::Unexpected {
                            pos: from,
                            what: "bad utf-8",
                        }
                    })?;
                    out.push_str(s);
                    self.pos += len - 1;
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        let pos = self.pos;
        match self.bump() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{8}'),
            Some(b'f') => Ok('\u{c}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => {
                let hi = self.hex4(pos)?;
                if (0xd800..0xdc00).contains(&hi) {
                    // High surrogate: a low surrogate must follow.
                    if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                        return Err(JsonError::UnpairedSurrogate(pos));
                    }
                    let lo = self.hex4(pos)?;
                    if !(0xdc00..0xe000).contains(&lo) {
                        return Err(JsonError::UnpairedSurrogate(pos));
                    }
                    let cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                    char::from_u32(cp).ok_or(JsonError::UnpairedSurrogate(pos))
                } else if (0xdc00..0xe000).contains(&hi) {
                    Err(JsonError::UnpairedSurrogate(pos))
                } else {
                    char::from_u32(hi).ok_or(JsonError::BadUnicodeEscape(pos))
                }
            }
            Some(_) => Err(JsonError::BadEscape(pos)),
            None => Err(JsonError::Truncated),
        }
    }

    fn hex4(&mut self, pos: usize) -> Result<u32, JsonError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(JsonError::Truncated);
        }
        let mut v: u32 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or(JsonError::Truncated)?;
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(JsonError::BadUnicodeEscape(pos)),
            };
            v = (v << 4) | d as u32;
        }
        Ok(v)
    }

    /// Array items after the opening `[` up to the matching `]`.
    fn seq(&mut self, close: u8) -> Result<Vec<Json>, JsonError> {
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(close) {
            self.pos += 1;
            return Ok(items);
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b) if b == close => return Ok(items),
                Some(_) => {
                    return Err(JsonError::Unexpected {
                        pos: self.pos - 1,
                        what: "expected , or close",
                    })
                }
                None => return Err(JsonError::Truncated),
            }
        }
    }

    /// Object pairs after the opening `{` up to the matching `}`.
    fn object_pairs(&mut self) -> Result<Vec<(String, Json)>, JsonError> {
        let mut pairs = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(pairs);
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return match self.peek() {
                    Some(_) => Err(JsonError::Unexpected {
                        pos: self.pos,
                        what: "object key must be a string",
                    }),
                    None => Err(JsonError::Truncated),
                };
            }
            let key = self.string()?;
            self.ws();
            if self.bump() != Some(b':') {
                return match self.peek() {
                    Some(_) => Err(JsonError::Unexpected {
                        pos: self.pos - 1,
                        what: "expected :",
                    }),
                    None => Err(JsonError::Truncated),
                };
            }
            self.ws();
            let value = self.value()?;
            pairs.push((key, value));
            self.ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(pairs),
                Some(_) => {
                    return Err(JsonError::Unexpected {
                        pos: self.pos - 1,
                        what: "expected , or }",
                    })
                }
                None => return Err(JsonError::Truncated),
            }
        }
    }
}

/// Length of a UTF-8 sequence from its first byte.
fn utf8_len(first: u8) -> usize {
    match first {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Json {
        Json::Str(v.to_string())
    }

    #[test]
    fn writer_shapes() {
        // The exact JSON-RPC request shape the demo emits.
        let req = Json::Object(vec![
            ("jsonrpc".into(), s("2.0")),
            ("id".into(), Json::Int(1)),
            ("method".into(), s("eth_chainId")),
            ("params".into(), Json::Array(vec![])),
        ]);
        assert_eq!(
            req.to_string(),
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#
        );
        // Escapes.
        assert_eq!(s("a\"b\\c\nd\u{1}").to_string(), r#""a\"b\\c\nd\u0001""#);
    }

    #[test]
    fn writer_roundtrips_through_parser() {
        let v = Json::Object(vec![
            (
                "a".into(),
                Json::Array(vec![Json::Int(-42), Json::Bool(true), Json::Null]),
            ),
            ("b".into(), s("héllo \"world\" 😀")),
        ]);
        let text = v.to_string();
        assert_eq!(parse(&text).unwrap(), v);
    }

    #[test]
    fn parse_basic_values() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse(" true ").unwrap(), Json::Bool(true));
        assert_eq!(
            parse("-170141183460469231731687303715884105728").unwrap(),
            Json::Int(i128::MIN)
        );
        assert_eq!(parse("0").unwrap(), Json::Int(0));
        assert_eq!(parse(r#""hi\n😀""#).unwrap(), s("hi\n😀"));
        assert_eq!(
            parse(r#"{"a":[1,{"b":null}],"c":false}"#).unwrap(),
            Json::Object(vec![
                (
                    "a".into(),
                    Json::Array(vec![
                        Json::Int(1),
                        Json::Object(vec![("b".into(), Json::Null)])
                    ])
                ),
                ("c".into(), Json::Bool(false)),
            ])
        );
        // Unicode escapes: BMP, surrogate pair, escaped quote.
        assert_eq!(parse(r#""é""#).unwrap(), s("é"));
        assert_eq!(parse(r#""😀""#).unwrap(), s("😀"));
        assert_eq!(parse(r#""\"""#).unwrap(), s("\""));
    }

    #[test]
    fn parse_rejects_malformed_input() {
        let bad = [
            "",
            "{",
            "[",
            "\"",
            "{\"a\":}",
            "{\"a\" 1}",
            "{a:1}",
            "[1,]",
            "[1 2]",
            "{\"a\":1,}",
            "01",
            "-",
            "1.",
            "1e",
            "1e+",
            "0x10",
            "nul",
            "nulll",
            "truex",
            "\"\\q\"",
            "\"\\u12\"",
            "\"\\uZZZZ\"",
            "\"\\ud800\"",
            "\"\\ud800x\"",
            "\"\\udc00\"",
            "\"\u{1f}\"",
            "1 2",
            "[] ]",
            "[[]",
            "{}",
            "}",
        ];
        for input in bad {
            // The two valid ones in the list are checked separately below.
            if input == "{}" {
                continue;
            }
            assert!(parse(input).is_err(), "must reject: {input:?}");
        }
        assert_eq!(parse("{}").unwrap(), Json::Object(vec![]));
        assert_eq!(parse("[ ]").unwrap(), Json::Array(vec![]));
        // Floats parse (responses carry them, e.g. gasUsedRatio).
        assert_eq!(parse("1.5").unwrap(), Json::Float(1.5));
        assert_eq!(parse("-0.5e3").unwrap(), Json::Float(-500.0));
        assert_eq!(parse("[0.5,0.25]").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn parse_enforces_depth_cap() {
        let mut deep = String::new();
        for _ in 0..MAX_DEPTH {
            deep.push('[');
        }
        assert!(matches!(parse(&deep), Err(JsonError::Truncated)));
        deep.push_str(&"]".repeat(MAX_DEPTH));
        assert!(parse(&deep).is_ok(), "exactly MAX_DEPTH is fine");
        let too_deep = format!("[{deep}]");
        assert!(matches!(parse(&too_deep), Err(JsonError::DepthLimit(_))));
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes() {
        // A mini fuzz run: every prefix/shuffle of a hostile seed corpus
        // must return Ok or Err — never panic. Deterministic, no RNG.
        let seeds: &[&[u8]] = &[
            b"{\"a\":[1,2,{\"b\":\"\\ud83d\\ude00\"}]}",
            b"\xff\xfe{\"a\":\xc3\xa9}",
            b"[[[[[[[[[[",
            b"\"\\u",
            b"-0.5e999",
            b"\x00\x01\x02",
            b"null null",
            b"\"\xf0\x9f\x98\x80\"", // "😀" as raw UTF-8 bytes
        ];
        for seed in seeds {
            for cut in 0..=seed.len() {
                if let Ok(text) = std::str::from_utf8(&seed[..cut]) {
                    let _ = parse(text); // must not panic
                }
            }
            // Byte-flipped variants.
            for i in 0..seed.len() {
                let mut m = seed.to_vec();
                m[i] ^= 0xff;
                if let Ok(text) = std::str::from_utf8(&m) {
                    let _ = parse(text); // must not panic
                }
            }
        }
    }

    #[test]
    fn accessors() {
        let v = parse(r#"{"result":"0xaa36a7","id":7,"ok":true,"arr":[1]}"#).unwrap();
        assert_eq!(v.get("result").and_then(Json::as_str), Some("0xaa36a7"));
        assert_eq!(v.get("id").and_then(Json::as_int), Some(7));
        assert_eq!(v.get("ok").and_then(Json::as_bool), Some(true));
        assert_eq!(v.get("arr").and_then(Json::as_array).unwrap().len(), 1);
        assert_eq!(v.get("missing"), None);
        assert!(Json::Null.is_null());
        assert!(!Json::Int(0).is_null());
    }
}

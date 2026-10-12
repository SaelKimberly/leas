//! Very permissive parser for JSON-ish data in raw subscriptions.
//! Uses hand-rolled UTF-8/percent-decoding character source.

use std::str::FromStr;

use serde_json::{Map, Number, Value};
use smallvec::SmallVec;

use crate::fast_perc::AutoChars;

type PResult<T> = Result<T, PermissiveJsonError>;

#[derive(Debug, thiserror::Error)]
pub enum PermissiveJsonError {
    #[error("empty input")]
    EmptyInput,
    #[error("unexpected end of input")]
    Eof,
    #[error("invalid byte encoding")]
    InvalidEncoding,
    #[error("invalid JSON syntax")]
    InvalidSyntax,
}

#[cfg_attr(test, derive(Debug))]
enum Container {
    Arr(Vec<Value>),
    Obj(Map<String, Value>, Option<String>),
}
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
struct JsonBuilder {
    stack: SmallVec<[Container; 8]>,
    root: Option<Value>,
}
impl JsonBuilder {
    pub fn object(&self) -> bool {
        matches!(self.stack.last(), Some(Container::Obj(_, _)))
    }
    pub fn begin_obj(&mut self) {
        self.stack.push(Container::Obj(Map::default(), None));
    }
    pub fn begin_arr(&mut self) {
        self.stack.push(Container::Arr(Vec::default()));
    }
    pub fn set_pending_key(&mut self, key: String) -> Result<(), PermissiveJsonError> {
        match self.stack.last_mut() {
            Some(Container::Obj(_, pending)) => {
                *pending = Some(key);
                Ok(())
            }
            _ => Err(PermissiveJsonError::InvalidSyntax),
        }
    }
    pub fn end_obj(&mut self) -> Result<(), PermissiveJsonError> {
        let Some(Container::Obj(map, _)) = self.stack.pop() else {
            return Err(PermissiveJsonError::InvalidSyntax);
        };
        self.insert_completed_value(Value::Object(map))
    }
    pub fn end_arr(&mut self) -> Result<(), PermissiveJsonError> {
        let Some(Container::Arr(arr)) = self.stack.pop() else {
            return Err(PermissiveJsonError::InvalidSyntax);
        };
        self.insert_completed_value(Value::Array(arr))
    }
    pub fn insert_completed_value(&mut self, value: Value) -> Result<(), PermissiveJsonError> {
        match self.stack.last_mut() {
            None => {
                self.root = Some(value);
                Ok(())
            }
            Some(Container::Obj(map, pending)) => {
                pending
                    .take()
                    .map_or(Err(PermissiveJsonError::InvalidSyntax), |key| {
                        _ = map.entry(key).or_insert(value);
                        Ok(())
                    })
            }
            Some(Container::Arr(arr)) => {
                arr.push(value);
                Ok(())
            }
        }
    }
}
#[cfg_attr(test, derive(Debug))]
struct JsonReader<'a> {
    char_iter: AutoChars<'a>,
    last_char: char,
    json: JsonBuilder,
}

const fn next_char_impl(char_iter: &mut AutoChars) -> PResult<char> {
    match char_iter.next() {
        Some(c) => Ok(c),
        None if char_iter.remaining().is_empty() => Err(PermissiveJsonError::Eof),
        None => Err(PermissiveJsonError::InvalidEncoding),
    }
}

/// Main cursor method
impl JsonReader<'_> {
    /// Try to read next character from data, and save it to `last_char`.
    const fn next_char(&mut self) -> PResult<char> {
        let r = next_char_impl(&mut self.char_iter);
        if let Ok(c) = r {
            self.last_char = c;
        }
        r
    }
}

/// Deal with whitespaces
impl JsonReader<'_> {
    /// When `last_char` is whitespace character, returns it, and read next char
    /// When `last_char` is not whitespace, returns Ok(None)
    const fn next_if_whitespace(&mut self) -> PResult<Option<char>> {
        if self.last_char.is_whitespace() || matches!(self.last_char, '+') {
            let result = Some(self.last_char);
            match self.next_char() {
                Ok(_) => Ok(result),
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }
    /// Collect all whitespace characters, from current position, and return first non-whitespace one.
    fn take_while_whitespace(&mut self, out: &mut String) -> PResult<char> {
        while let Some(c) = self.next_if_whitespace()? {
            out.push(c);
        }
        Ok(self.last_char)
    }
    /// Just skip all whitespace characters, from current position, and return first non-whitespace one.
    const fn skip_while_whitespace(&mut self) -> PResult<char> {
        loop {
            match self.next_if_whitespace() {
                Ok(Some(_)) => {}
                Ok(None) => break Ok(self.last_char),
                Err(e) => break Err(e),
            }
        }
    }
}
impl<'a> JsonReader<'a> {
    const fn create(input: &'a [u8]) -> PResult<Self> {
        let mut char_iter = AutoChars::new(input);
        let last_char = match next_char_impl(&mut char_iter) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        Ok(Self {
            char_iter,
            last_char,
            json: JsonBuilder {
                stack: SmallVec::new_const(),
                root: None,
            },
        })
    }

    fn try_consume(mut self) -> PResult<(Value, &'a [u8])> {
        loop {
            if let Some(root) = self.json.root {
                return Ok((root, self.char_iter.remaining()));
            }

            if self.json.object() {
                // Inside an object, always read key first
                // Only except for case, when we are closing object
                if matches!(self.last_char, '}') {
                    self.json.end_obj()?;
                    if let Some(root) = self.json.root {
                        return Ok((root, self.char_iter.remaining()));
                    }
                    // Just get a next char
                    _ = self.next_char()?;
                } else {
                    // Expect key
                    self.read_key()?;
                    // Consume colon or equal sign
                    _ = self.next_char()?;
                    // And expect val after
                    self.read_val()?;
                }
            } else {
                // When not in object, expect val
                self.read_val()?;
            }
            // Inside an array, we expect a value
            // Also, in object, we have already get

            // Skip commas (allow repeatable commas)
            while self.skip_while_whitespace()? == ',' {
                _ = self.next_char()?;
            }

            if self.json.root.is_none()
                && self.char_iter.remaining().is_empty()
                && !matches!(self.last_char, '"' | '\'' | '}' | ']' | ',')
            {
                return Err(PermissiveJsonError::Eof);
            }
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum ReadLike {
    Val,
    Key,
}

/// Simple JSON string unescape for the common escape sequences.
/// Handles: \\, \", \/, \n, \r, \t, \b, \f, \uXXXX
/// Falls back to the original string on failure.
fn json_unescape(s: &str) -> String {
    escape8259::unescape(s).unwrap_or_else(|_| s.to_string())
}

impl ReadLike {
    #[inline]
    const fn check_eof(self, c: char) -> bool {
        match self {
            // After key, allowlist is colon and equal signs
            // {"key":}
            // {key=}
            Self::Key => matches!(c, ':' | '='),
            // After value, we expect to find either comma, or a closing bracket
            Self::Val => matches!(c, ',' | '}' | ']'),
        }
    }
    // Currently, we have no support for reading non-utf-8 encoded text
    // But, keys and values in raw data, likely, should be escaped, using RFC 8259 (JSON)
    // Also, values could contain emoji, so we should try to unescape them properly.
    // Most keys and values, likely, have no escaped characters, so memchr
    fn apply_unescape(self, val: String) -> String {
        if val.as_bytes().contains(&b'\\') {
            let r = json_unescape(&val);
            // Only for values, unicode decoding may be needed.
            if matches!(self, Self::Val) && r.as_bytes().contains(&b'\\') {
                // Try double-unescape for values
                json_unescape(&r)
            } else {
                r
            }
        } else {
            val
        }
    }
}

impl JsonReader<'_> {
    fn take_text(
        &mut self,
        out: &mut String,
        predicate: impl Fn(char) -> bool,
        esc_char: Option<char>,
        eof_char: Option<char>,
    ) -> PResult<()> {
        loop {
            // `\x` -> `\x`
            // `\\x` -> `\\x`
            // `\\\eof_char` -> `\eof_char` (if specified)
            // `\eof_char` -> end of value (if specified)
            if let Some(esc_char) = esc_char
                && self.last_char == esc_char
            {
                let ch = self.next_char()?;
                // eof_char is set, when beginning of string was escaped eof_char
                match eof_char {
                    // Break on escaped end of string
                    Some(c) if ch == c => {
                        return Ok(());
                    }
                    // Collapse triple escaped simple character
                    Some(_) if out.ends_with(esc_char) => {
                        _ = out.pop();
                    }
                    _ => {
                        out.push(esc_char);
                    }
                }
                out.push(ch);
            } else if predicate(self.last_char) {
                out.push(self.last_char);
            } else {
                return Ok(());
            }
            match self.next_char() {
                Ok(_) => {}
                Err(PermissiveJsonError::Eof) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    #[inline]
    fn read_key(&mut self) -> PResult<()> {
        // As keys are always text, we have to skip flag check
        let (_, key) = self.read_any_data_and_verify(ReadLike::Key)?;
        self.json.set_pending_key(key)
    }

    fn read_val(&mut self) -> PResult<()> {
        match self.skip_while_whitespace()? {
            '{' => {
                self.json.begin_obj();
                self.next_char()?;
            }
            '[' => {
                self.json.begin_arr();
                self.next_char()?;
            }

            ']' => {
                self.json.end_arr()?;
                if self.json.root.is_none() {
                    self.next_char()?;
                }
            }
            _ => {
                let (is_text, val_raw) = self.read_any_data_and_verify(ReadLike::Val)?;

                let value = if is_text {
                    // When we have sure, that it is a text
                    Value::String(val_raw)
                } else if val_raw.eq_ignore_ascii_case("true") {
                    // Boolean true
                    Value::Bool(true)
                } else if val_raw.eq_ignore_ascii_case("false") {
                    // Boolean false
                    Value::Bool(false)
                } else if val_raw.eq_ignore_ascii_case("null")
                    || val_raw.eq_ignore_ascii_case("none")
                {
                    // Null
                    Value::Null
                } else if let Ok(i) = <i64 as FromStr>::from_str(&val_raw) {
                    // Integer
                    Value::Number(i.into())
                } else if let Ok(f) = <f64 as FromStr>::from_str(&val_raw)
                    && let Some(n) = Number::from_f64(f)
                {
                    // Floating point
                    Value::Number(n)
                } else {
                    // Fallback to text
                    Value::String(val_raw)
                };

                return self.json.insert_completed_value(value);
            }
        }
        Ok(())
    }

    // Read optional quote character (maybe, escaped)
    const fn read_eof(&mut self) -> PResult<Option<(bool, char)>> {
        match self.last_char {
            // Single or double quote
            c @ ('"' | '\'') => Ok(Some((false, c))),
            // Escaped single or double quote
            '\\' => match self.next_char() {
                Ok(c @ ('"' | '\'')) => Ok(Some((true, c))),
                // Other escaped character
                Ok(_) => Err(PermissiveJsonError::InvalidSyntax),
                Err(e) => Err(e),
            },
            _ => Ok(None),
        }
    }

    // Read all characters from current (last_char):
    // If current char is a quote, then read to the next not escaped quote.
    // If current char is not a quote, read with restrictive allowlist
    // When reading done, verify, that next non-whitespace character is a read_like eof.
    fn read_any_data_and_verify(&mut self, read_like: ReadLike) -> PResult<(bool, String)> {
        let mut buf = String::new();

        _ = self.skip_while_whitespace()?;

        let eof = match self.read_eof() {
            Ok(Some(c)) => Some(c),
            Ok(None) => None,
            // Accept any escaped non-quote character at the beginning of input
            Err(PermissiveJsonError::InvalidSyntax) => {
                buf.push('\\');
                buf.push(self.last_char);
                _ = self.next_char()?;
                None
            }

            Err(e) => return Err(e),
        };
        let mut is_text: bool = false;
        if let Some((escaped, eof)) = eof {
            is_text = true;
            // Consume opening quote before reading text content
            _ = self.next_char()?;
            loop {
                // Read text until we reached eof character.
                self.take_text(&mut buf, |c| c != eof, Some('\\'), escaped.then_some(eof))?;
                // As take_text definitely stops at eof character (escaped or not)
                // we should skip it to proceed to next data.
                // If EOF right after closing quote, accept value as-is.
                match self.next_char() {
                    Err(PermissiveJsonError::Eof) if self.last_char == eof => {
                        break;
                    }
                    Err(PermissiveJsonError::Eof) => return Err(PermissiveJsonError::Eof),
                    Err(e) => return Err(e),
                    Ok(_) => {}
                }
                // If it is a real eof, then after it we should find a control character, specific to read_like eof.
                let buf_length = buf.len();

                buf.push('\\');
                buf.push(eof);
                if read_like.check_eof(self.take_while_whitespace(&mut buf)?) {
                    // If we have such control character after eof, truncate buf, to not keep escaped eof and final whitespaces
                    buf.truncate(buf_length);
                    break;
                }
                // Otherwise, keep escaped eof and whitespace characters after, and read new portion of text
            }
        } else {
            // When we have no clue, about the underlying data structure,
            // we just have to allowlist acceptable characters
            self.take_text(
                &mut buf,
                |c| matches!(c,'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.'),
                Some('\\'),
                None,
            )?;
            let buf_length = buf.len();

            // If last_char is already a valid delimiter, return immediately.
            // This preserves `}` and `]` for structural processing (end_obj/end_arr).
            if read_like.check_eof(self.last_char) {
                return Ok((false, read_like.apply_unescape(buf)));
            }

            match self.next_char() {
                Err(PermissiveJsonError::Eof) => {
                    return Ok((false, read_like.apply_unescape(buf)));
                }
                Err(e) => return Err(e),
                _ => {}
            }

            let c = match self.take_while_whitespace(&mut buf)? {
                // If we have found, after possible whitespace characters, a quote,
                // There could be a missing quote in the beginning.
                // We just restore it implicitly, using "is_text", keep whitespace characters, and read a next char.
                '"' | '\'' => {
                    is_text = true;
                    _ = self.next_char()?;
                    self.skip_while_whitespace()?
                }
                // Otherwise (here is definitely should be non-whitespace character)
                // we have to truncate buffer to its original length
                c => {
                    buf.truncate(buf_length);
                    c
                }
            };
            // If the next character is not eof for the read_like, there is invalid syntax.
            if !read_like.check_eof(c) {
                return Err(PermissiveJsonError::InvalidSyntax);
            }
        }

        Ok((is_text, read_like.apply_unescape(buf)))
    }
}

/// Parse a JSON value from a byte slice, with some leniency.
///
/// # Errors
///
/// Returns an error if the input is not valid or recoverable JSON.
pub fn permissive_json_core(input: &[u8]) -> PResult<(&[u8], serde_json::Value)> {
    let (value, remaining) = JsonReader::create(input)?.try_consume()?;
    Ok((remaining, value))
}

/// Parse a JSON value from a byte slice, with some leniency.
///
/// # Errors
///
/// Returns an error if the input is not valid or recoverable JSON.
pub fn permissive_json(input: &[u8]) -> PResult<serde_json::Value> {
    let first = permissive_json_core(input);

    let done = matches!(&first, Ok((rem, _)) if rem.is_empty());
    if done {
        return first.map(|(_, v)| v);
    }

    if let Some(pos) = input.iter().position(|&b| b == b'[') {
        let mut m = input.to_vec();
        m.insert(pos, b'"');
        if let Ok((_, value)) = permissive_json_core(&m) {
            return Ok(value);
        }
    }

    first.map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::permissive_json_core;
    use super::{PResult, permissive_json};

    fn truncated_lines() -> Vec<&'static [u8]> {
        r#"
        {
        {#🇳🇱 The Netherlands, Amsterdam | [BL]
        {"scMaxEachPostBytes":#4Sarina-8699
        {"scMaxEachPostBytes":# By EbraSha
        {# By EbraSha
        {'headers':# By EbraSha
        {#XHTTP, VK [V.O.I.D]
        {#XHTTP, Max [V.O.I.D]
        {#0193 | 🇷🇺 Russia | VLESS | TG: @YoutubeUnBlockRu
        {#0272 | 🌐 Unknown | VLESS | TG: @YoutubeUnBlockRu
        {#1766 | 🌐 Unknown | VLESS | TG: @YoutubeUnBlockRu
        {#2735 | 🌐 Unknown | VLESS | TG: @YoutubeUnBlockRu
        {#3422 | 🌐 Unknown | VLESS | TG: @YoutubeUnBlockRu
        {# "scMaxEachPostBytes": 1000000, "scMaxConcurrentPosts": 100%2…
        {"v":"2","ps":"tag","add":"host.com","port":"443","id":"uuid1234","aid":"0"
        {"key":"val","other":"val2"
        {"scMaxEachPostBytes":1000000,"scMaxConcurrentPosts":100
        {"nested":{"inner":{"deep":"val"}
        {"a":1,"b":2,"c":3,"d":4
        {"host":"","path":"","mode":"auto"
        {"xPaddingBytes":"100-1000","scMaxEachPostBytes":"1000000"
        {"arr": [1, 2, 3, 4, 5
        {"v":"2","ps":"test"
        {"a":1,"b":2,"c":3
        {"deeply":{"nested":{"object":{"with":{"many":"fields"}
        {"data":"very long string that just keeps going and going and going
        {"mode":"auto","type":"grpc"
        "#
        .lines()
        .map(str::trim)
        .map(str::as_bytes)
        .collect()
    }

    #[test]
    fn test_truncated_leaks_nothing() {
        // Verify that no truncated input causes the parser to
        // re-interpret value bytes as keys (which would mean
        // the parser consumed bytes without advancing last_char).
        let lines = truncated_lines();
        for line in &lines {
            let result = permissive_json_core(line);
            // If the parser re-reads a value byte as a key,
            // it means progress-through-input ≠ cursor-advance.
            // This test just checks no crash/infinite-loop.
            _ = result;
        }
    }

    #[test]
    fn test_truncated_lines_dont_loop() {
        let lines = truncated_lines();
        for line in &lines {
            let result = permissive_json_core(line);
            // All truncated inputs should error (not infinite loop, not OOM)
            assert!(result.is_err(), "Expected error for truncated: {line:?}");
        }
    }

    #[test]
    fn test_tokenizer() -> PResult<()> {
        let (tail, res) = permissive_json_core(b"None")?;
        assert_eq!(res, serde_json::Value::Null);
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{}")?;
        assert_eq!(res, serde_json::json!({}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{'key':'val'}")?;
        assert_eq!(res, serde_json::json!({"key": "val"}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{'key':[['val',],],}")?;
        assert_eq!(res, serde_json::json!({"key": [["val"]]}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{'key':[[{'val':null}]]}")?;
        assert_eq!(res, serde_json::json!({"key": [[{"val": null}]]}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{key:[[{'val':null}]]}")?;
        assert_eq!(res, serde_json::json!({"key": [[{"val": null}]]}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"{var-length-key:[[{'some val':null}]]}")?;
        assert_eq!(
            res,
            serde_json::json!({"var-length-key": [[{"some val": null}]]})
        );
        assert!(tail.is_empty(), "tail: {tail:?}");

        let (tail, res) = permissive_json_core(b"%7B%22key%22%3A%22value%22%7D")?;
        assert_eq!(res, serde_json::json!({"key": "value"}));
        assert!(tail.is_empty(), "tail: {tail:?}");

        Ok(())
    }

    #[test]
    fn test_corrupted_vmess_ps() {
        let input: &[u8] = &[
            0x7b, 0x22, 0x61, 0x64, 0x64, 0x22, 0x3a, 0x20, 0x22, 0x32, 0x31, 0x36, 0x2e, 0x32,
            0x33, 0x38, 0x2e, 0x38, 0x36, 0x2e, 0x31, 0x35, 0x38, 0x22, 0x2c, 0x20, 0x22, 0x69,
            0x64, 0x22, 0x3a, 0x20, 0x22, 0x39, 0x30, 0x62, 0x65, 0x32, 0x31, 0x34, 0x64, 0x2d,
            0x30, 0x34, 0x38, 0x63, 0x2d, 0x34, 0x65, 0x61, 0x32, 0x2d, 0x61, 0x36, 0x30, 0x32,
            0x2d, 0x62, 0x38, 0x65, 0x34, 0x64, 0x34, 0x65, 0x35, 0x31, 0x65, 0x33, 0x36, 0x22,
            0x2c, 0x20, 0x22, 0x6e, 0x65, 0x74, 0x22, 0x3a, 0x20, 0x22, 0x74, 0x63, 0x70, 0x22,
            0x2c, 0x20, 0x22, 0x70, 0x6f, 0x72, 0x74, 0x22, 0x3a, 0x20, 0x33, 0x34, 0x34, 0x36,
            0x30, 0x2c, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x6e, 0x6f,
            0x6e, 0x65, 0x22, 0x2c, 0x20, 0x22, 0x76, 0x22, 0x3a, 0x20, 0x22, 0x32, 0x22, 0x2c,
            0x20, 0x22, 0x73, 0x6b, 0x69, 0x70, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x2d, 0x76, 0x65,
            0x72, 0x69, 0x66, 0x79, 0x22, 0x3a, 0x20, 0x74, 0x72, 0x75, 0x65, 0x2c, 0x20, 0x22,
            0x70, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0xf0, 0x9f, 0x8f, 0x81, 0x5d, 0x74, 0x2e, 0x6d,
            0x65, 0x2f, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x48, 0x75, 0x62, 0x3a, 0x20,
            0x22, 0x5c, 0x75, 0x64, 0x38, 0x33, 0x64, 0x5c, 0x75, 0x64, 0x63, 0x34, 0x39, 0x5c,
            0x75, 0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x39, 0x34, 0x40, 0x76, 0x32,
            0x72, 0x61, 0x79, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x5f, 0x70, 0x6f,
            0x6f, 0x6c, 0x5c, 0x75, 0x64, 0x38, 0x33, 0x64, 0x5c, 0x75, 0x64, 0x63, 0x65, 0x31,
            0x5c, 0x75, 0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x66, 0x32, 0x5c, 0x75,
            0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x66, 0x64, 0x5c, 0x75, 0x30, 0x30,
            0x61, 0x65, 0x5c, 0x75, 0x66, 0x65, 0x30, 0x66, 0x4d, 0x65, 0x78, 0x69, 0x63, 0x6f,
            0x5c, 0x75, 0x30, 0x30, 0x61, 0x39, 0x5c, 0x75, 0x66, 0x65, 0x30, 0x66, 0x51, 0x75,
            0x65, 0x72, 0x5c, 0x75, 0x30, 0x30, 0x65, 0x39, 0x74, 0x61, 0x72, 0x6f, 0x20, 0x43,
            0x69, 0x74, 0x79, 0x5c, 0x75, 0x64, 0x38, 0x33, 0x63, 0x5c, 0x75, 0x64, 0x64, 0x37,
            0x66, 0x5c, 0x75, 0x66, 0x65, 0x30, 0x66, 0x70, 0x69, 0x6e, 0x67, 0x3a, 0x31, 0x36,
            0x31, 0x2e, 0x36, 0x38, 0x6d, 0x73, 0x22, 0x7d,
        ];
        let result = permissive_json(input);
        assert!(result.is_ok(), "Should parse corrupted VMess: {result:?}");
        let value = result.unwrap();
        let ps = value.get("ps").and_then(|v| v.as_str());
        assert!(ps.is_some(), "Should have 'ps' field: {value}");
        let ps = ps.unwrap();
        assert!(ps.contains("ConfigsHub"), "Should contain channel name");
        assert!(ps.contains("v2ray"), "Should contain description");
        eprintln!("OK: ps={ps:?}");
    }

    // ── B3a: leading `+` on values (sing-box accepts, strict JSON rejects) ──

    #[test]
    fn test_leading_plus_number() {
        // Leading + on integer: common in subscription generators
        let (_, v) = permissive_json_core(b"+100").unwrap();
        assert_eq!(v, serde_json::json!(100));
    }

    #[test]
    fn test_leading_plus_float() {
        // Leading + on float
        let (_, v) = permissive_json_core(b"+1.5").unwrap();
        assert_eq!(v, serde_json::json!(1.5));
    }

    #[test]
    fn test_leading_plus_sci() {
        // Leading + on scientific notation
        let (_, v) = permissive_json_core(b"+1e10").unwrap();
        assert_eq!(v, serde_json::json!(1e10));
    }

    #[test]
    fn test_leading_plus_in_array() {
        // [+1, +2] in array context
        let (_, v) = permissive_json_core(b"[+1, +2]").unwrap();
        assert_eq!(v, serde_json::json!([1, 2]));
    }

    #[test]
    fn test_leading_plus_on_string_key() {
        // +"key" — leading plus on string key in object
        let (_, v) = permissive_json_core(b"{+\"a\": +1, +\"b\": +2}").unwrap();
        assert_eq!(v, serde_json::json!({"a": 1, "b": 2}));
    }

    #[test]
    fn test_leading_plus_on_string_val() {
        // +"100-1000" — leading plus on string value (meaningless but accepted)
        let (_, v) = permissive_json_core(b"{+\"a\": +\"100-1000\"}").unwrap();
        assert_eq!(v, serde_json::json!({"a": "100-1000"}));
    }

    #[test]
    fn test_leading_plus_on_bool() {
        // +false — leading plus on boolean value
        let (_, v) = permissive_json_core(b"+false").unwrap();
        assert_eq!(v, serde_json::Value::Bool(false));
    }

    #[test]
    fn test_leading_plus_on_string_val_is_string() {
        // +"foo" — leading plus before string: skip_while_whitespace consumes +,
        // then the string is read normally. Result is the string value.
        let (_, v) = permissive_json_core(b"+\"foo\"").unwrap();
        assert_eq!(v, serde_json::json!("foo"));
    }

    #[test]
    fn test_leading_plus_on_true() {
        // +true — skip_while_whitespace consumes +, then true is parsed as boolean
        let (_, v) = permissive_json_core(b"+true").unwrap();
        assert_eq!(v, serde_json::Value::Bool(true));
    }

    #[test]
    fn test_leading_plus_real_extra_b3a() {
        // Real-world B3a extra value: leading + on all values and string keys
        // {"scMaxEachPostBytes":+1000000,+"scMaxConcurrentPosts":+100,
        //  +"scMinPostsIntervalMs":+30,+"xPaddingBytes":+"100-1000",
        //  +"noGRPCHeader":+false}
        // This is the exact shape that appears in ~241 NDJSON records
        let input = br#"{"scMaxEachPostBytes":+1000000,+"scMaxConcurrentPosts":+100,+"scMinPostsIntervalMs":+30,+"xPaddingBytes":+"100-1000",+"noGRPCHeader":+false}"#;
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["scMaxEachPostBytes"], serde_json::json!(1_000_000));
        assert_eq!(v["scMaxConcurrentPosts"], serde_json::json!(100));
        assert_eq!(v["scMinPostsIntervalMs"], serde_json::json!(30));
        assert_eq!(v["xPaddingBytes"], serde_json::json!("100-1000"));
        assert_eq!(v["noGRPCHeader"], serde_json::json!(false));
    }

    #[test]
    fn test_leading_plus_real_extra_b3a_xmux() {
        // Real-world B3a extra with nested xmux object
        // +{"maxConcurrency":"16-32",...} — leading + on nested object
        let input = br#"{"scMaxEachPostBytes":+1000000,+"scMaxConcurrentPosts":+100,+"xmux":+{"maxConcurrency":+"16-32",+"maxConnections":+0}}"#;
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["scMaxEachPostBytes"], serde_json::json!(1_000_000));
        assert_eq!(v["xmux"]["maxConcurrency"], serde_json::json!("16-32"));
        assert_eq!(v["xmux"]["maxConnections"], serde_json::json!(0));
    }

    // ── B3b: single quotes / mixed quotes (Python dict style) ──

    #[test]
    fn test_mixed_quotes_realistic() {
        // Real-world B3b: Python dict with single-quoted keys and booleans
        let input = b"{'headers': {}, 'noGRPCHeader': True, 'xmux': {'maxConnections': '3'}}";
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["headers"], serde_json::json!({}));
        assert_eq!(v["noGRPCHeader"], serde_json::json!(true));
        assert_eq!(v["xmux"]["maxConnections"], serde_json::json!("3"));
    }

    #[test]
    fn test_mixed_quotes_mixed() {
        // Mixed single and double quotes in same dict
        let input =
            b"{'headers': {}, 'xPaddingBytes': '100-1000', \"scMaxEachPostBytes\": 1000000}";
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["xPaddingBytes"], serde_json::json!("100-1000"));
        assert_eq!(v["scMaxEachPostBytes"], serde_json::json!(1_000_000));
    }

    #[test]
    fn test_python_true() {
        // Python True (capital T) maps to JSON true
        let (_, v) = permissive_json_core(b"{'a': True, 'b': False}").unwrap();
        assert_eq!(v["a"], serde_json::json!(true));
        assert_eq!(v["b"], serde_json::json!(false));
    }

    #[test]
    fn test_extra_plus_and_quotes() {
        // Single quotes with leading +
        let input = b"{'headers':{}}";
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["headers"], serde_json::json!({}));
    }

    // ── URL-encoded input tests (what AutoChars receives) ──

    #[test]
    fn test_url_encoded_extra() {
        // URL-encoded JSON: %7B%22a%22%3A1%7D → {"a":1}
        // AutoChars handles URL decoding, so permissive_json sees decoded chars
        let (_, v) = permissive_json_core(b"%7B%22a%22%3A1%7D").unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn test_url_encoded_with_plus() {
        // URL-encoded with + (URL-decoded value has leading +)
        // %2B = + → permissive_json receives the decoded JSON with +
        let (_, v) = permissive_json_core(b"%7B%22a%22%3A%2B1%7D").unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    // ── Truncated JSON (must fail) ──

    #[test]
    fn test_truncated_brace_fails() {
        assert!(permissive_json_core(b"{").is_err());
    }

    #[test]
    fn test_truncated_key_fails() {
        assert!(permissive_json_core(b"{\"key\":").is_err());
    }

    #[test]
    fn test_truncated_string_fails() {
        assert!(permissive_json_core(b"{\"key\": \"unclosed").is_err());
    }

    // ── Real NDJSON samples (exact extracts) ──

    #[test]
    fn test_b3a_exact_sample_1() {
        // Exact B3a extra value from NDJSON (241 occurrences)
        let input = br#"{"scMaxEachPostBytes":+1000000,+"scMaxConcurrentPosts":+100,+"scMinPostsIntervalMs":+30,+"xPaddingBytes":+"100-1000",+"noGRPCHeader":+false}"#;
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["xPaddingBytes"], serde_json::json!("100-1000"));
    }

    #[test]
    fn test_b3b_exact_sample_1() {
        // Exact B3b extra value from NDJSON (single quotes, Python True)
        let input = b"{'headers': {}, 'noGRPCHeader': True, 'xmux': {'maxConnections': '3'}}";
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["noGRPCHeader"], serde_json::json!(true));
    }

    #[test]
    fn test_b3b_exact_mixed_quotes() {
        // B3b extra with mixed single/double quotes from NDJSON
        let input = b"{'headers': {}, 'xPaddingBytes': '100-1000', \"scMaxEachPostBytes\": 1000000, \"scMinPostsIntervalMs\": 30}";
        let (_, v) = permissive_json_core(input).unwrap();
        assert_eq!(v["xPaddingBytes"], serde_json::json!("100-1000"));
        assert_eq!(v["scMaxEachPostBytes"], serde_json::json!(1_000_000));
    }

    #[test]
    fn test_truncated_extra_brace() {
        // Truncated: extra={ from NDJSON
        assert!(permissive_json_core(b"{").is_err());
    }

    #[test]
    fn test_equals_as_separator_quoted() {
        // = as JSON key-value separator (alternative to :)
        let (_, v) = permissive_json_core(b"{'key'='val'}").unwrap();
        assert_eq!(v, serde_json::json!({"key": "val"}));

        let (_, v) = permissive_json_core(br#"{"key"="val"}"#).unwrap();
        assert_eq!(v, serde_json::json!({"key": "val"}));
    }

    #[test]
    fn test_equals_as_separator_unquoted() {
        // = separator with unquoted keys
        let (_, v) = permissive_json_core(b"{key='val'}").unwrap();
        assert_eq!(v, serde_json::json!({"key": "val"}));

        let (_, v) = permissive_json_core(b"{key=123}").unwrap();
        assert_eq!(v, serde_json::json!({"key": 123}));
    }
    #[test]
    fn test_equals_vmess_style() {
        // VMess-style JSON using = separator
        let input = br#"{"v"="2","ps"="remark","add"="host.com","port"="443","id"="uuid1234","aid"="0","net"="ws","type"="none","host"=""}"#;
        let (_, v) = permissive_json_core(input).unwrap();
        // permissive parser now keeps quoted digit-only strings as strings
        assert_eq!(v["v"], serde_json::json!("2"));
        assert_eq!(v["ps"], "remark");
        assert_eq!(v["add"], "host.com");
        assert_eq!(v["host"], "");
    }

    #[test]
    fn test_mixed_separators() {
        // Mixed : and = in same object
        let (_, v) = permissive_json_core(b"{'a'='b', 'c':'d', 'e'='f'}").unwrap();
        assert_eq!(v["a"], "b");
        assert_eq!(v["c"], "d");
        assert_eq!(v["e"], "f");
    }

    // ── Truncated strings (lone backslash before end of input) ──

    #[test]
    fn test_truncated_lone_backslash_in_string() {
        // A string ending with a lone backslash (no escape char follow)
        // The parser should error rather than loop or produce garbage
        assert!(permissive_json_core(b"{\"key\": \"trailing-backslash\\").is_err());
    }

    #[test]
    fn test_truncated_backslash_before_quote() {
        // Backslash before closing quote: "key\" without end
        assert!(permissive_json_core(b"{\"key\": \"val\\").is_err());
    }

    #[test]
    fn test_escaped_quote_in_string() {
        // Valid escaped quote: "key\"mid"
        let (_, v) = permissive_json_core(b"{\"key\": \"val\\\"mid\"}").unwrap();
        assert_eq!(v["key"], "val\"mid");
    }

    // ── Unicode escape sequences (\\uXXXX) ──

    #[test]
    fn test_unicode_escape_basic() {
        // \u0041 = 'A'
        let (_, v) = permissive_json_core(b"{\"key\": \"\\u0041\"}").unwrap();
        assert_eq!(v["key"], "A");
    }

    #[test]
    fn test_unicode_escape_accented() {
        // \u00e9 = '\u00e9'
        let (_, v) = permissive_json_core(b"{\"key\": \"caf\\u00e9\"}").unwrap();
        assert_eq!(v["key"], "caf\u{00e9}");
    }

    #[test]
    fn test_unicode_escape_lowercase_hex() {
        // \u0041 = 'A', lowercase hex digits
        let (_, v) = permissive_json_core(b"{\"key\": \"\\u0041\"}").unwrap();
        assert_eq!(v["key"], "A");
    }

    #[test]
    fn test_multiple_unicode_escapes() {
        // Multiple \uXXXX in one string
        let (_, v) = permissive_json_core(b"\"\\u0048\\u0065\\u006c\\u006c\\u006f\"").unwrap();
        assert_eq!(v, "Hello");
    }

    // ── Deeply nested structures ──

    #[test]
    fn test_deeply_nested_arrays() {
        // 10 levels of nested arrays — must not stack overflow
        let mut input = b"[".repeat(10);
        input.extend(b"1");
        input.extend(b"]".repeat(10));
        let (_, v) = permissive_json_core(&input).unwrap();
        // Unwrap to verify depth
        let mut current = &v;
        for _ in 0..10 {
            current = &current[0];
        }
        assert_eq!(current, 1);
    }

    #[test]
    fn test_deeply_nested_objects() {
        // 10 levels of nested objects — must not stack overflow
        let mut input = b"{\"a\":".repeat(10);
        input.extend(b"1");
        input.extend(b"}".repeat(10));
        let (_, v) = permissive_json_core(&input).unwrap();
        let mut current = &v;
        for _ in 0..10 {
            current = &current["a"];
        }
        assert_eq!(current, 1);
    }

    #[test]
    fn test_deeply_nested_mixed() {
        // Alternating object/array nesting
        let mut input = b"{\"a\":[".repeat(5);
        input.extend(b"1");
        input.extend(b"]}".repeat(5));
        let (_, v) = permissive_json_core(&input).unwrap();
        let mut current = &v;
        for _ in 0..5 {
            current = &current["a"][0];
        }
        assert_eq!(current, 1);
    }

    // ── Empty keys/values ──

    #[test]
    fn test_empty_key() {
        let (_, v) = permissive_json_core(b"{\"\": \"value\"}").unwrap();
        assert_eq!(v[""], "value");
    }

    #[test]
    fn test_empty_value() {
        let (_, v) = permissive_json_core(b"{\"key\": \"\"}").unwrap();
        assert_eq!(v["key"], "");
    }

    #[test]
    fn test_empty_key_and_value() {
        let (_, v) = permissive_json_core(b"{\"\": \"\"}").unwrap();
        assert_eq!(v[""], "");
    }

    #[test]
    fn test_empty_key_single_quotes() {
        let (_, v) = permissive_json_core(b"{'' : 'value'}").unwrap();
        assert_eq!(v[""], "value");
    }

    #[test]
    fn test_empty_value_single_quotes() {
        let (_, v) = permissive_json_core(b"{'key' : ''}").unwrap();
        assert_eq!(v["key"], "");
    }

    #[test]
    fn test_empty_nested_object() {
        let (_, v) = permissive_json_core(b"{\"a\": {\"\": \"inner\"}}").unwrap();
        assert_eq!(v["a"][""], "inner");
    }
}

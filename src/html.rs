//! HTML5 character-reference decoding, including legacy semicolonless forms.
//! The names/values come from html-escape's WHATWG table.
const LEGACY: &str = "AElig AMP Aacute Acirc Agrave Aring Atilde Auml COPY Ccedil ETH Eacute Ecirc Egrave Euml GT Iacute Icirc Igrave Iuml LT Ntilde Oacute Ocirc Ograve Oslash Otilde Ouml QUOT REG THORN Uacute Ucirc Ugrave Uuml Yacute aacute acirc acute aelig agrave amp aring atilde auml brvbar ccedil cedil cent copy curren deg divide eacute ecirc egrave eth euml frac12 frac14 frac34 gt iacute icirc iexcl igrave iquest iuml laquo lt macr micro middot nbsp not ntilde oacute ocirc ograve ordf ordm oslash otilde ouml para plusmn pound quot raquo reg sect shy sup1 sup2 sup3 szlig thorn times uacute ucirc ugrave uml uuml yacute yen yuml";
const C1: [u32; 32] = [
    0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039,
    0x152, 0x8d, 0x17d, 0x8f, 0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x2dc,
    0x2122, 0x161, 0x203a, 0x153, 0x9d, 0x17e, 0x178,
];

fn character(n: u32) -> Option<char> {
    let n = if (0x80..=0x9f).contains(&n) {
        C1[(n - 0x80) as usize]
    } else {
        n
    };
    if n == 0 || n > 0x10ffff || (0xd800..=0xdfff).contains(&n) {
        return Some('\u{fffd}');
    }
    if matches!(n, 1..=8 | 0xb | 0xe..=0x1f | 0x7f | 0xfdd0..=0xfdef) || n & 0xffff >= 0xfffe {
        return None;
    }
    char::from_u32(n)
}

pub fn decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut pos = 0;
    while let Some(relative) = memchr::memchr(b'&', &bytes[pos..]) {
        let start = pos + relative;
        out.push_str(&input[pos..start]);
        let mut end = start + 1;
        if bytes.get(end) == Some(&b'#') {
            end += 1;
            let hex = matches!(bytes.get(end), Some(b'x' | b'X'));
            if hex {
                end += 1;
            }
            let digits = end;
            while bytes.get(end).is_some_and(|b| {
                if hex {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                }
            }) {
                end += 1;
            }
            if end > digits {
                let n = u32::from_str_radix(&input[digits..end], if hex { 16 } else { 10 })
                    .unwrap_or(u32::MAX);
                if let Some(c) = character(n) {
                    out.push(c);
                }
                if bytes.get(end) == Some(&b';') {
                    end += 1;
                }
                pos = end;
                continue;
            }
        } else {
            while end - start <= 32 && bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
                end += 1;
            }
            let mut found = false;
            for stop in (start + 2..=end).rev() {
                let name = &bytes[start + 1..stop];
                let terminated = bytes.get(stop) == Some(&b';');
                if !terminated
                    && !LEGACY
                        .split_ascii_whitespace()
                        .any(|s| s.as_bytes() == name)
                {
                    continue;
                }
                if let Ok(i) = html_escape::NAMED_ENTITIES.binary_search_by(|(n, _)| n.cmp(&name)) {
                    out.push_str(html_escape::NAMED_ENTITIES[i].1);
                    pos = stop + usize::from(terminated);
                    found = true;
                    break;
                }
            }
            if found {
                continue;
            }
        }
        out.push('&');
        pos = start + 1;
    }
    out.push_str(&input[pos..]);
    out
}

/// Minimal DEX file parser for resolving constant pool references.
/// Parses string_ids, type_ids, proto_ids, field_ids, method_ids tables
/// from DEX files extracted from APK archives.

/// A cross-reference: a code location that loads a specific string constant.
pub struct StringXref {
    pub string_idx: u32,
    pub class_name: String,       // JNI sig e.g. "Lcom/test/Foo;"
    pub method_name: String,
    pub proto: String,            // "(I)V" style
    pub method_idx: u32,          // index into method_ids table
    pub code_offset: u32,         // byte offset within the method's insns
}

/// Resolved constant pool data from a single DEX file.
pub struct DexData {
    pub strings: Vec<String>,
    pub types: Vec<String>,       // type descriptor strings
    pub methods: Vec<MethodRef>,
    pub fields: Vec<FieldRef>,
    pub class_defs: Vec<String>,  // type descriptors of defined classes
    pub string_xrefs: Vec<StringXref>,  // const-string cross-references
    /// Raw DEX bytes (used by the DEX patcher for in-place method replacement).
    pub raw: Vec<u8>,
}

pub struct MethodRef {
    pub class_name: String,
    pub method_name: String,
    pub proto: String,            // "(I)V" style
}

pub struct FieldRef {
    pub class_name: String,
    pub field_name: String,
    pub field_type: String,
}

impl DexData {
    /// Resolve a string index to its value.
    pub fn get_string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(|s| s.as_str())
    }

    /// Resolve a type index to a short display name.
    pub fn get_type_short(&self, idx: u32) -> Option<String> {
        self.types.get(idx as usize).map(|t| crate::commands::short_type(t))
    }

    /// Resolve a method index to "ClassName.methodName(params)" display string.
    pub fn get_method_display(&self, idx: u32) -> Option<String> {
        self.methods.get(idx as usize).map(|m| {
            let cls = crate::commands::short_class(&m.class_name);
            if m.proto.is_empty() {
                format!("{}.{}", cls, m.method_name)
            } else {
                let proto = crate::commands::short_proto(&m.proto);
                format!("{}.{}{}", cls, m.method_name, proto)
            }
        })
    }

    /// Resolve a field index to "ClassName.fieldName:Type" display string.
    pub fn get_field_display(&self, idx: u32) -> Option<String> {
        self.fields.get(idx as usize).map(|f| {
            let cls = crate::commands::short_class(&f.class_name);
            let typ = crate::commands::short_type(&f.field_type);
            format!("{}.{}:{}", cls, f.field_name, typ)
        })
    }

    /// Check if this DEX defines the given class (JNI signature, e.g. "Lcom/test/Foo;").
    pub fn has_class(&self, class_sig: &str) -> bool {
        self.class_defs.iter().any(|c| c == class_sig)
    }
}

/// Read little-endian u16 from byte slice.
fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 1 < data.len() {
        u16::from_le_bytes([data[off], data[off + 1]])
    } else {
        0
    }
}

/// Read little-endian u32 from byte slice.
fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 3 < data.len() {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    } else {
        0
    }
}

/// Decode ULEB128 value, return (value, bytes_consumed).
fn decode_uleb128(data: &[u8], off: usize) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    let mut i = off;
    loop {
        if i >= data.len() {
            break;
        }
        let b = data[i];
        result |= ((b & 0x7f) as u32) << shift;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            break;
        }
    }
    (result, i - off)
}

/// Read a MUTF-8 string from string_data_item at the given offset.
fn read_string_data(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    // ULEB128 length (in UTF-16 code units, not bytes)
    let (_utf16_len, leb_size) = decode_uleb128(data, off);
    let str_start = off + leb_size;

    // Read until null byte (MUTF-8 is null-terminated)
    let mut end = str_start;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }

    // MUTF-8 is mostly compatible with UTF-8 for ASCII/BMP
    String::from_utf8_lossy(&data[str_start..end]).into_owned()
}

/// Parse a DEX file from raw bytes. Returns None if invalid.
pub fn parse_dex(data: &[u8]) -> Option<DexData> {
    // Check magic: "dex\n0XX\0"
    if data.len() < 0x70 {
        return None;
    }
    if &data[0..4] != b"dex\n" {
        return None;
    }

    // Read header fields
    let string_ids_size = read_u32(data, 0x38) as usize;
    let string_ids_off = read_u32(data, 0x3C) as usize;
    let type_ids_size = read_u32(data, 0x40) as usize;
    let type_ids_off = read_u32(data, 0x44) as usize;
    let proto_ids_size = read_u32(data, 0x48) as usize;
    let proto_ids_off = read_u32(data, 0x4C) as usize;
    let field_ids_size = read_u32(data, 0x50) as usize;
    let field_ids_off = read_u32(data, 0x54) as usize;
    let method_ids_size = read_u32(data, 0x58) as usize;
    let method_ids_off = read_u32(data, 0x5C) as usize;
    let class_defs_size = read_u32(data, 0x60) as usize;
    let class_defs_off = read_u32(data, 0x64) as usize;

    // Parse string_ids → string_data
    let mut strings = Vec::with_capacity(string_ids_size);
    for i in 0..string_ids_size {
        let str_data_off = read_u32(data, string_ids_off + i * 4) as usize;
        strings.push(read_string_data(data, str_data_off));
    }

    // Parse type_ids (each is u32 index into strings)
    let mut types = Vec::with_capacity(type_ids_size);
    for i in 0..type_ids_size {
        let str_idx = read_u32(data, type_ids_off + i * 4) as usize;
        let name = strings.get(str_idx).cloned().unwrap_or_default();
        types.push(name);
    }

    // Parse proto_ids for method signatures
    // Each proto_id: shorty_idx(u32) + return_type_idx(u32) + parameters_off(u32) = 12 bytes
    struct ProtoId {
        return_type: String,
        params: Vec<String>,
    }
    let mut protos = Vec::with_capacity(proto_ids_size);
    for i in 0..proto_ids_size {
        let base = proto_ids_off + i * 12;
        let return_type_idx = read_u32(data, base + 4) as usize;
        let params_off = read_u32(data, base + 8) as usize;

        let return_type = types.get(return_type_idx).cloned().unwrap_or_default();
        let mut params = Vec::new();

        if params_off != 0 && params_off + 4 <= data.len() {
            // type_list: u32 size + u16[] type_idx
            let param_count = read_u32(data, params_off) as usize;
            for j in 0..param_count {
                let type_idx = read_u16(data, params_off + 4 + j * 2) as usize;
                let ptype = types.get(type_idx).cloned().unwrap_or_default();
                params.push(ptype);
            }
        }

        protos.push(ProtoId { return_type, params });
    }

    // Parse method_ids: class_idx(u16) + proto_idx(u16) + name_idx(u32) = 8 bytes
    let mut methods = Vec::with_capacity(method_ids_size);
    for i in 0..method_ids_size {
        let base = method_ids_off + i * 8;
        let class_idx = read_u16(data, base) as usize;
        let proto_idx = read_u16(data, base + 2) as usize;
        let name_idx = read_u32(data, base + 4) as usize;

        let class_name = types.get(class_idx).cloned().unwrap_or_default();
        let method_name = strings.get(name_idx).cloned().unwrap_or_default();

        let proto = if let Some(p) = protos.get(proto_idx) {
            let params_str: String = p.params.join("");
            format!("({}){}", params_str, p.return_type)
        } else {
            String::new()
        };

        methods.push(MethodRef { class_name, method_name, proto });
    }

    // Parse field_ids: class_idx(u16) + type_idx(u16) + name_idx(u32) = 8 bytes
    let mut fields = Vec::with_capacity(field_ids_size);
    for i in 0..field_ids_size {
        let base = field_ids_off + i * 8;
        let class_idx = read_u16(data, base) as usize;
        let type_idx = read_u16(data, base + 2) as usize;
        let name_idx = read_u32(data, base + 4) as usize;

        let class_name = types.get(class_idx).cloned().unwrap_or_default();
        let field_name = strings.get(name_idx).cloned().unwrap_or_default();
        let field_type = types.get(type_idx).cloned().unwrap_or_default();

        fields.push(FieldRef { class_name, field_name, field_type });
    }

    // Parse class_defs to know which classes this DEX defines
    // Each class_def: class_idx(u32) + ... = 32 bytes
    let mut class_defs = Vec::with_capacity(class_defs_size);
    for i in 0..class_defs_size {
        let base = class_defs_off + i * 32;
        let class_idx = read_u32(data, base) as usize;
        let name = types.get(class_idx).cloned().unwrap_or_default();
        class_defs.push(name);
    }

    // Build string cross-references by scanning method bytecodes
    let string_xrefs = build_string_xrefs(data, class_defs_size, class_defs_off, &types, &strings, &methods);

    Some(DexData {
        strings,
        types,
        methods,
        fields,
        class_defs,
        string_xrefs,
        raw: data.to_vec(),
    })
}

/// Scan all method bytecodes in the DEX for const-string instructions,
/// building a cross-reference table of string_idx → code locations.
fn build_string_xrefs(
    data: &[u8],
    class_defs_size: usize,
    class_defs_off: usize,
    types: &[String],
    strings: &[String],
    methods: &[MethodRef],
) -> Vec<StringXref> {
    let mut xrefs = Vec::new();

    for i in 0..class_defs_size {
        let base = class_defs_off + i * 32;
        let class_idx = read_u32(data, base) as usize;
        let class_data_off = read_u32(data, base + 24) as usize;
        if class_data_off == 0 {
            continue; // no class data (interface/marker)
        }
        let class_name = types.get(class_idx).cloned().unwrap_or_default();

        // Parse class_data_item (ULEB128-encoded)
        let mut pos = class_data_off;
        if pos >= data.len() { continue; }

        let (static_fields_size, n) = decode_uleb128(data, pos); pos += n;
        let (instance_fields_size, n) = decode_uleb128(data, pos); pos += n;
        let (direct_methods_size, n) = decode_uleb128(data, pos); pos += n;
        let (virtual_methods_size, n) = decode_uleb128(data, pos); pos += n;

        // Skip encoded_field entries: field_idx_diff(uleb) + access_flags(uleb)
        for _ in 0..(static_fields_size + instance_fields_size) {
            let (_, n) = decode_uleb128(data, pos); pos += n; // field_idx_diff
            let (_, n) = decode_uleb128(data, pos); pos += n; // access_flags
        }

        // Parse encoded_method entries
        let mut method_idx_acc: u32 = 0;
        for _ in 0..(direct_methods_size + virtual_methods_size) {
            let (method_idx_diff, n) = decode_uleb128(data, pos); pos += n;
            let (_, n) = decode_uleb128(data, pos); pos += n; // access_flags
            let (code_off, n) = decode_uleb128(data, pos); pos += n;

            method_idx_acc += method_idx_diff;
            let mid = method_idx_acc as usize;

            if code_off == 0 { continue; } // abstract/native
            let code_off = code_off as usize;

            // code_item: registers(2) + ins(2) + outs(2) + tries(2) + debug(4) + insns_size(4) + insns[]
            if code_off + 16 > data.len() { continue; }
            let insns_size = read_u32(data, code_off + 12) as usize; // in 2-byte units
            let insns_off = code_off + 16;
            if insns_off + insns_size * 2 > data.len() { continue; }

            let (method_name, proto) = if let Some(m) = methods.get(mid) {
                (m.method_name.clone(), m.proto.clone())
            } else {
                continue;
            };

            // Scan instructions for const-string (0x1a) and const-string/jumbo (0x1b)
            scan_insns_for_const_string(
                data, insns_off, insns_size,
                &class_name, &method_name, &proto, mid as u32,
                strings.len(), &mut xrefs,
            );
        }
    }

    xrefs
}

/// Scan a method's instruction stream for const-string references.
fn scan_insns_for_const_string(
    data: &[u8],
    insns_off: usize,
    insns_size: usize,   // in 2-byte code units
    class_name: &str,
    method_name: &str,
    proto: &str,
    method_idx: u32,
    string_count: usize,
    xrefs: &mut Vec<StringXref>,
) {
    let mut pc: usize = 0; // in code units

    while pc < insns_size {
        let byte_off = insns_off + pc * 2;
        if byte_off + 1 >= data.len() { break; }

        let opcode = data[byte_off]; // low byte of first code unit

        match opcode {
            // const-string vAA, string@BBBB  - format 21c, width 2 units
            0x1a => {
                if pc + 1 < insns_size && byte_off + 3 < data.len() {
                    let str_idx = read_u16(data, byte_off + 2) as usize;
                    if str_idx < string_count {
                        xrefs.push(StringXref {
                            string_idx: str_idx as u32,
                            class_name: class_name.to_string(),
                            method_name: method_name.to_string(),
                            proto: proto.to_string(),
                            method_idx,
                            code_offset: (pc * 2) as u32,
                        });
                    }
                }
                pc += 2;
            }
            // const-string/jumbo vAA, string@BBBBBBBB  - format 31c, width 3 units
            0x1b => {
                if pc + 2 < insns_size && byte_off + 5 < data.len() {
                    let str_idx = read_u32(data, byte_off + 2) as usize;
                    if str_idx < string_count {
                        xrefs.push(StringXref {
                            string_idx: str_idx as u32,
                            class_name: class_name.to_string(),
                            method_name: method_name.to_string(),
                            proto: proto.to_string(),
                            method_idx,
                            code_offset: (pc * 2) as u32,
                        });
                    }
                }
                pc += 3;
            }
            // All other opcodes: use width table to skip
            _ => {
                pc += dalvik_insn_width(opcode) as usize;
            }
        }
    }
}

/// Scan a DEX for all methods that contain an invoke of `target_class.target_method`.
/// Returns deduplicated list of (class_name, method_name, proto) callers.
/// Stops early and sets `timed_out` if scanning exceeds `timeout`.
pub fn find_method_callers(
    dex: &DexData,
    target_class: &str,  // JNI form: "Landroid/os/Debug;"
    target_method: &str, // "isDebuggerConnected"
    timeout: std::time::Duration,
) -> (Vec<(String, String, String)>, bool) {
    let data = &dex.raw;
    let start = std::time::Instant::now();
    let mut seen = std::collections::HashSet::new();
    let mut callers = Vec::new();

    // We need class_defs to walk methods — re-parse the header
    if data.len() < 112 { return (callers, false); }
    let class_defs_size = read_u32(data, 96) as usize;
    let class_defs_off  = read_u32(data, 100) as usize;

    for i in 0..class_defs_size {
        // Timeout checked per class — low overhead
        if start.elapsed() > timeout {
            return (callers, true);
        }

        let base = class_defs_off + i * 32;
        if base + 32 > data.len() { break; }

        let class_idx      = read_u32(data, base) as usize;
        let class_data_off = read_u32(data, base + 24) as usize;
        if class_data_off == 0 { continue; }

        let class_name = dex.types.get(class_idx).cloned().unwrap_or_default();

        let mut pos = class_data_off;
        if pos >= data.len() { continue; }

        let (static_fields,   n) = decode_uleb128(data, pos); pos += n;
        let (instance_fields, n) = decode_uleb128(data, pos); pos += n;
        let (direct_methods,  n) = decode_uleb128(data, pos); pos += n;
        let (virtual_methods, n) = decode_uleb128(data, pos); pos += n;

        for _ in 0..(static_fields + instance_fields) {
            let (_, n) = decode_uleb128(data, pos); pos += n;
            let (_, n) = decode_uleb128(data, pos); pos += n;
        }

        let mut method_idx_acc: u32 = 0;
        for _ in 0..(direct_methods + virtual_methods) {
            let (diff, n) = decode_uleb128(data, pos); pos += n;
            let (_,    n) = decode_uleb128(data, pos); pos += n; // access_flags
            let (code_off, n) = decode_uleb128(data, pos); pos += n;
            method_idx_acc += diff;

            if code_off == 0 { continue; }
            let code_off = code_off as usize;
            if code_off + 16 > data.len() { continue; }

            let insns_size = read_u32(data, code_off + 12) as usize;
            let insns_off  = code_off + 16;
            if insns_off + insns_size * 2 > data.len() { continue; }

            let mid = method_idx_acc as usize;
            let (method_name, proto) = if let Some(m) = dex.methods.get(mid) {
                (m.method_name.clone(), m.proto.clone())
            } else {
                continue;
            };

            // Scan instructions for invoke opcodes
            let mut pc: usize = 0;
            while pc < insns_size {
                let byte_off = insns_off + pc * 2;
                if byte_off + 1 >= data.len() { break; }
                let opcode = data[byte_off];

                // invoke-kind (35c): 0x6e–0x72, invoke-kind/range (3rc): 0x74–0x78
                let is_invoke = matches!(opcode, 0x6e..=0x72 | 0x74..=0x78);
                if is_invoke && byte_off + 4 <= data.len() {
                    let ref_idx = read_u16(data, byte_off + 2) as usize;
                    if let Some(m) = dex.methods.get(ref_idx) {
                        if m.class_name == target_class && m.method_name == target_method {
                            let key = (class_name.clone(), method_name.clone(), proto.clone());
                            if seen.insert(key) {
                                callers.push((class_name.clone(), method_name.clone(), proto.clone()));
                            }
                        }
                    }
                }

                let width = if matches!(opcode, 0x6e..=0x72 | 0x74..=0x78) { 3 }
                            else { dalvik_insn_width(opcode) as usize };
                if width == 0 { break; }
                pc += width;
            }
        }
    }

    (callers, false)
}

/// Return instruction width in 2-byte code units for a Dalvik opcode.
fn dalvik_insn_width(opcode: u8) -> u32 {
    match opcode {
        // 10x: 1 unit
        0x00 | 0x0e | 0x73 | 0x7e..=0x8f => 1,
        // 12x, 11n, 11x, 10t: 1 unit
        0x01 | 0x04 | 0x07 | 0x0a..=0x0d | 0x0f..=0x12
        | 0x1d..=0x1e | 0x21 | 0x27 | 0x28 | 0x3e..=0x43
        | 0x7b..=0x7d | 0xb0..=0xcf => 1,
        // 22x, 21t, 21s, 21h, 21c, 23x, 22b, 22t, 22s, 22c, 20t: 2 units
        0x02..=0x03 | 0x05..=0x06 | 0x08..=0x09 | 0x13 | 0x15..=0x16
        | 0x19..=0x1a | 0x1c | 0x1f..=0x20 | 0x22..=0x23
        | 0x29 | 0x2d..=0x3d | 0x44..=0x6d
        | 0x90..=0xaf | 0xd0..=0xe2 => 2,
        // 35c, 3rc, 31i, 31t, 31c, 30t: 3 units
        0x14 | 0x17 | 0x1b | 0x24..=0x26 | 0x2a..=0x2c
        | 0x6e..=0x72 | 0x74..=0x78 => 3,
        // 51l: 5 units (const-wide)
        0x18 => 5,
        // fill-array-data, packed-switch, sparse-switch payloads
        // handled as special pseudo-opcodes  - use 1 as fallback
        _ => 1,
    }
}

/// Extract DEX files from an APK (ZIP) archive.
/// Uses the ZIP Central Directory for reliable entry discovery — immune to fake/padding
/// local file header entries that confuse forward byte-scanning parsers.
pub fn extract_dex_from_apk(apk_data: &[u8]) -> Vec<Vec<u8>> {
    let n = apk_data.len();
    if n < 22 {
        return Vec::new();
    }

    // --- Find End of Central Directory (EOCD) record ---
    // Signature: PK\x05\x06. Scan backwards allowing up to 65535-byte comment.
    let min_eocd = if n >= 65535 + 22 { n - 65535 - 22 } else { 0 };
    let mut eocd_pos = None;
    for i in (min_eocd..=n.saturating_sub(22)).rev() {
        if apk_data[i] == b'P' && apk_data[i+1] == b'K'
            && apk_data[i+2] == 5 && apk_data[i+3] == 6
        {
            eocd_pos = Some(i);
            break;
        }
    }
    let eocd = match eocd_pos {
        Some(p) => p,
        None => return Vec::new(),
    };

    let cd_size   = read_u32(apk_data, eocd + 12) as usize;
    let cd_offset = read_u32(apk_data, eocd + 16) as usize;
    if cd_offset.saturating_add(cd_size) > n {
        return Vec::new();
    }

    // --- Walk Central Directory entries ---
    // Each entry has accurate offsets to its local file header,
    // so fake/padding entries in the local-header area are bypassed entirely.
    let mut dex_files = Vec::new();
    let mut cd_pos = cd_offset;
    let cd_end = cd_offset + cd_size;

    while cd_pos + 46 <= cd_end {
        // Central directory signature: PK\x01\x02
        if apk_data[cd_pos] != b'P' || apk_data[cd_pos+1] != b'K'
            || apk_data[cd_pos+2] != 1 || apk_data[cd_pos+3] != 2
        {
            break;
        }

        let compression  = read_u16(apk_data, cd_pos + 10);
        let comp_size    = read_u32(apk_data, cd_pos + 20) as usize;
        let name_len     = read_u16(apk_data, cd_pos + 28) as usize;
        let extra_len    = read_u16(apk_data, cd_pos + 30) as usize;
        let comment_len  = read_u16(apk_data, cd_pos + 32) as usize;
        let local_offset = read_u32(apk_data, cd_pos + 42) as usize;

        let name_start = cd_pos + 46;
        let entry_end  = name_start + name_len + extra_len + comment_len;

        let name = if name_start + name_len <= cd_end {
            std::str::from_utf8(&apk_data[name_start..name_start + name_len]).unwrap_or("")
        } else {
            ""
        };

        if is_dex_entry(name) && (compression == 0 || compression == 8) {
            // Jump to local file header, read past its variable fields.
            if local_offset + 30 <= n {
                let local_name_len  = read_u16(apk_data, local_offset + 26) as usize;
                let local_extra_len = read_u16(apk_data, local_offset + 28) as usize;
                let data_start = local_offset + 30 + local_name_len + local_extra_len;
                let data_end   = data_start + comp_size;
                if data_end <= n {
                    if compression == 0 {
                        // Stored: grab raw bytes directly.
                        dex_files.push(apk_data[data_start..data_end].to_vec());
                    } else {
                        // Deflated (apktool-rebuilt APKs): decompress.
                        use std::io::Read as _;
                        let mut decoder = flate2::read::DeflateDecoder::new(
                            &apk_data[data_start..data_end]
                        );
                        let mut out = Vec::new();
                        if decoder.read_to_end(&mut out).is_ok() {
                            dex_files.push(out);
                        }
                    }
                }
            }
        }

        cd_pos = entry_end;
    }

    dex_files
}

fn is_dex_entry(name: &str) -> bool {
    // classes.dex, classes2.dex, classes3.dex, ...
    name == "classes.dex" || (name.starts_with("classes") && name.ends_with(".dex"))
}

/// Parse raw bytes as DEX or as a ZIP/JAR/APK containing DEX files.
/// Used for dynamically loaded DEX payloads received from the agent.
pub fn parse_dex_bytes(data: &[u8]) -> Result<Vec<DexData>, String> {
    // Try raw DEX first (magic "dex\n")
    if data.len() >= 4 && &data[0..4] == b"dex\n" {
        if let Some(dex) = parse_dex(data) {
            return Ok(vec![dex]);
        }
    }
    // Try as ZIP container (magic "PK\x03\x04")
    if data.len() >= 4 && data[0] == b'P' && data[1] == b'K' && data[2] == 3 && data[3] == 4 {
        let blobs = extract_dex_from_apk(data);
        if !blobs.is_empty() {
            let mut result = Vec::new();
            for blob in &blobs {
                if let Some(dex) = parse_dex(blob) {
                    result.push(dex);
                }
            }
            if !result.is_empty() {
                return Ok(result);
            }
        }
    }
    Err("Not a valid DEX or ZIP/JAR/APK file".into())
}

/// Load and parse all DEX files from an APK at the given path.
pub fn load_apk(path: &str) -> Result<Vec<DexData>, String> {
    let apk_data = std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let dex_blobs = extract_dex_from_apk(&apk_data);

    if dex_blobs.is_empty() {
        return Err("No DEX files found in APK".into());
    }

    let mut result = Vec::new();
    for (i, blob) in dex_blobs.iter().enumerate() {
        match parse_dex(blob) {
            Some(dex) => result.push(dex),
            None => return Err(format!("Failed to parse DEX #{}", i)),
        }
    }

    Ok(result)
}

/// Pull APK from device via ADB, save to temp file, return local path.
pub fn adb_pull_apk(package: &str) -> Result<String, String> {
    // Get APK path from device
    let output = std::process::Command::new("adb")
        .args(["shell", "pm", "path", package])
        .output()
        .map_err(|e| format!("adb failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let apk_path = stdout
        .lines()
        .find(|l| l.starts_with("package:"))
        .map(|l| l.trim_start_matches("package:").trim())
        .ok_or_else(|| format!("Package '{}' not found on device", package))?
        .to_string();

    // Pull to temp dir
    let temp_dir = std::env::temp_dir();
    let local_path = temp_dir.join("dexbgd_apk.apk");
    let local_str = local_path.to_string_lossy().to_string();

    let pull = std::process::Command::new("adb")
        .args(["pull", &apk_path, &local_str])
        .output()
        .map_err(|e| format!("adb pull failed: {}", e))?;

    if !pull.status.success() {
        return Err(format!(
            "adb pull failed: {}",
            String::from_utf8_lossy(&pull.stderr)
        ));
    }

    Ok(local_str)
}

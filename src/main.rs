// extcheck: detecta si la extension de un archivo coincide con su contenido real (magic bytes).
// Uso: extcheck <archivo|carpeta> [mas rutas...]
// Sin dependencias externas, solo std.
//
// Ademas de la firma, refina el diagnostico:
//   - ZIP: mira los nombres internos (word/ => docx, xl/ => xlsx, ppt/ => pptx, ...)
//   - PE: distingue exe / dll / sys leyendo el encabezado
//   - Sin firma: adivina si es texto (HTML, XML, JSON, script, Markdown...) o binario

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Pe,
    Elf,
    MachO,
    JavaClass, // CAFEBABE (ambiguo con Mach-O fat, se trata como class)
    Png,
    Jpeg,
    Gif,
    Pdf,
    Zip,
    Rar,
    SevenZ,
    Gzip,
    Mp3,
    Mp4,
    Unknown, // sin firma conocida (texto plano, scripts, etc.)
}

impl Kind {
    fn is_executable(self) -> bool {
        matches!(self, Kind::Pe | Kind::Elf | Kind::MachO)
    }
}

#[cfg(windows)]
fn launched_from_explorer() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    }
    let mut pids = [0u32; 2];
    unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) == 1 }
}

#[cfg(not(windows))]
fn launched_from_explorer() -> bool {
    false
}

fn detect(b: &[u8]) -> Kind {
    if b.starts_with(b"MZ") {
        Kind::Pe
    } else if b.starts_with(&[0x7F, b'E', b'L', b'F']) {
        Kind::Elf
    } else if b.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        || b.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || b.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || b.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
    {
        Kind::MachO
    } else if b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        Kind::JavaClass
    } else if b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Kind::Png
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Kind::Jpeg
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Kind::Gif
    } else if b.starts_with(b"%PDF-") {
        Kind::Pdf
    } else if b.starts_with(&[b'P', b'K', 0x03, 0x04]) || b.starts_with(&[b'P', b'K', 0x05, 0x06]) {
        Kind::Zip
    } else if b.starts_with(b"Rar!\x1A\x07") {
        Kind::Rar
    } else if b.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
        Kind::SevenZ
    } else if b.starts_with(&[0x1F, 0x8B]) {
        Kind::Gzip
    } else if b.starts_with(b"ID3") || (b.len() >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0) {
        Kind::Mp3
    } else if b.len() >= 8 && &b[4..8] == b"ftyp" {
        Kind::Mp4
    } else {
        Kind::Unknown
    }
}

/// Que tipos de contenido son aceptables para una extension. None = extension desconocida.
fn expected(ext: &str) -> Option<&'static [Kind]> {
    Some(match ext {
        "exe" | "dll" | "sys" | "scr" | "ocx" => &[Kind::Pe],
        "so" | "elf" => &[Kind::Elf],
        "dylib" => &[Kind::MachO, Kind::JavaClass],
        "class" => &[Kind::JavaClass],
        "png" => &[Kind::Png],
        "jpg" | "jpeg" => &[Kind::Jpeg],
        "gif" => &[Kind::Gif],
        "pdf" => &[Kind::Pdf],
        "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "jar" | "apk" | "epub" | "xpi" => {
            &[Kind::Zip]
        }
        "rar" => &[Kind::Rar],
        "7z" => &[Kind::SevenZ],
        "gz" | "tgz" => &[Kind::Gzip],
        "mp3" => &[Kind::Mp3],
        "mp4" | "m4a" | "mov" => &[Kind::Mp4],
        // texto / scripts: no deben tener firma binaria alguna
        "txt" | "md" | "json" | "toml" | "yaml" | "yml" | "csv" | "html" | "css" | "js" | "ts"
        | "py" | "sh" | "rs" | "go" | "java" | "c" | "h" | "cpp" | "bat" | "ps1" => {
            &[Kind::Unknown]
        }
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Utilidades de lectura
// ---------------------------------------------------------------------------

fn read_at(f: &mut File, off: u64, len: usize) -> Option<Vec<u8>> {
    f.seek(SeekFrom::Start(off)).ok()?;
    let mut v = vec![0u8; len];
    f.read_exact(&mut v).ok()?;
    Some(v)
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32le(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

// ---------------------------------------------------------------------------
// Refinamiento: PE (exe / dll / sys)
// ---------------------------------------------------------------------------

/// Devuelve "dll", "sys" (subsistema nativo) o "exe" leyendo el encabezado PE.
fn pe_detail(f: &mut File) -> Option<&'static str> {
    let dos = read_at(f, 0, 0x40)?;
    let lfanew = u32le(&dos, 0x3C)? as u64;
    // firma (4) + COFF (20) + optional header hasta el campo Subsystem (offset 68 + 2)
    let h = read_at(f, lfanew, 24 + 70)?;
    if &h[0..4] != b"PE\0\0" {
        return None;
    }
    let characteristics = u16le(&h, 4 + 18)?;
    let subsystem = u16le(&h, 24 + 68)?;
    if characteristics & 0x2000 != 0 {
        Some("dll")
    } else if subsystem == 1 {
        Some("sys")
    } else {
        Some("exe")
    }
}

// ---------------------------------------------------------------------------
// Refinamiento: ZIP (mira los nombres del directorio central)
// ---------------------------------------------------------------------------

fn zip_names(f: &mut File) -> Option<Vec<String>> {
    let len = f.metadata().ok()?.len();
    let tail_len = len.min(65_557);
    let tail = read_at(f, len - tail_len, tail_len as usize)?;
    if tail.len() < 22 {
        return None;
    }

    // buscar el End Of Central Directory (PK\x05\x06) desde el final
    let eocd_pos = (0..=tail.len() - 22)
        .rev()
        .find(|&i| &tail[i..i + 4] == b"PK\x05\x06")?;
    let eocd = &tail[eocd_pos..];
    let cd_size = u32le(eocd, 12)? as usize;
    let cd_off = u32le(eocd, 16)? as u64;
    if cd_size == 0 || cd_size > 16 * 1024 * 1024 {
        return None;
    }
    let cd = read_at(f, cd_off, cd_size)?;

    let mut names = Vec::new();
    let mut pos = 0usize;
    while pos + 46 <= cd.len() && &cd[pos..pos + 4] == b"PK\x01\x02" && names.len() < 100_000 {
        let n = u16le(&cd, pos + 28)? as usize;
        let e = u16le(&cd, pos + 30)? as usize;
        let c = u16le(&cd, pos + 32)? as usize;
        let name = cd.get(pos + 46..pos + 46 + n)?;
        names.push(String::from_utf8_lossy(name).into_owned());
        pos += 46 + n + e + c;
    }
    Some(names)
}

/// Segun la estructura interna, que extensiones tienen sentido. None = zip generico.
fn zip_guess(names: &[String]) -> Option<&'static [&'static str]> {
    let starts = |p: &str| names.iter().any(|n| n.starts_with(p));
    let exact = |p: &str| names.iter().any(|n| n == p);

    if starts("word/") && exact("[Content_Types].xml") {
        Some(&["docx", "docm", "dotx", "dotm"])
    } else if starts("xl/") && exact("[Content_Types].xml") {
        Some(&["xlsx", "xlsm", "xltx", "xlsb"])
    } else if starts("ppt/") && exact("[Content_Types].xml") {
        Some(&["pptx", "pptm", "potx", "ppsx"])
    } else if exact("AndroidManifest.xml") {
        Some(&["apk", "xapk"])
    } else if exact("META-INF/container.xml") {
        Some(&["epub"])
    } else if exact("mimetype") && exact("content.xml") {
        Some(&["odt", "ods", "odp", "odg"])
    } else if exact("META-INF/MANIFEST.MF") {
        Some(&["jar", "war", "ear", "xpi", "zip"])
    } else {
        None
    }
}

const ZIP_FAMILY: &[&str] = &[
    "zip", "docx", "xlsx", "pptx", "odt", "ods", "jar", "apk", "epub", "xpi",
];

// ---------------------------------------------------------------------------
// Refinamiento: archivos sin firma (texto o binario desconocido)
// ---------------------------------------------------------------------------

/// Devuelve (descripcion, extension sugerida). La sugerencia solo aparece cuando hay
/// senales suficientes; en texto siempre es una estimacion, nunca una certeza.
fn text_guess(b: &[u8]) -> (&'static str, Option<&'static str>) {
    if b.is_empty() {
        return ("archivo vacio", None);
    }
    if b.contains(&0) {
        return ("binario sin firma conocida", None);
    }
    let b = if b.starts_with(&[0xEF, 0xBB, 0xBF]) { &b[3..] } else { b };
    let text = String::from_utf8_lossy(b).into_owned();
    let low = text.trim_start().to_lowercase();
    let first = low.lines().next().unwrap_or("");

    if low.starts_with("#!") {
        let ext = if first.contains("python") {
            "py"
        } else if first.contains("node") {
            "js"
        } else {
            "sh"
        };
        return ("script (shebang)", Some(ext));
    }
    if low.starts_with("<!doctype html") || low.starts_with("<html") {
        return ("HTML", Some("html"));
    }
    if low.starts_with("<?xml") {
        return ("XML", Some("xml"));
    }
    let json_like = low.starts_with('{')
        || (low.starts_with('[')
            && low[1..]
                .trim_start()
                .chars()
                .next()
                .map_or(false, |c| matches!(c, '{' | '"' | '[' | '0'..='9' | '-')));
    if json_like && low.contains('"') {
        return ("posible JSON", Some("json"));
    }

    let lines: Vec<&str> = text.lines().collect();
    let has = |p: &str| lines.iter().any(|l| l.trim_start().starts_with(p));

    // codigo fuente (senales fuertes)
    if has("#include") {
        return ("codigo C/C++", Some("c"));
    }
    if has("fn main") || has("use std::") || has("pub fn ") {
        return ("codigo Rust", Some("rs"));
    }
    if has("def ") || (has("import ") && !text.contains(';')) {
        return ("codigo Python", Some("py"));
    }

    // Markdown: cuantas familias de marcas distintas aparecen
    let heading = has("# ") || has("## ") || has("### ");
    let bullet = has("- ") || has("* ");
    let fence = has("```");
    let link = text.contains("](");
    let bold = text.contains("**");
    let score = [heading, bullet, fence, link, bold].iter().filter(|x| **x).count();
    if score >= 2 {
        ("texto con formato Markdown", Some("md"))
    } else if heading {
        ("texto (posible Markdown)", None)
    } else {
        ("texto plano", Some("txt"))
    }
}

fn kind_ext(k: Kind) -> Option<&'static str> {
    Some(match k {
        Kind::JavaClass => "class",
        Kind::Png => "png",
        Kind::Jpeg => "jpg",
        Kind::Gif => "gif",
        Kind::Pdf => "pdf",
        Kind::Rar => "rar",
        Kind::SevenZ => "7z",
        Kind::Gzip => "gz",
        Kind::Mp3 => "mp3",
        Kind::Mp4 => "mp4",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Verificacion
// ---------------------------------------------------------------------------

enum Verdict {
    Ok,
    Mismatch { high: bool },
    Warn, // la firma cuadra, pero el contenido interno sugiere otra extension
    UnknownExt,
}

struct Report {
    kind: Kind,
    verdict: Verdict,
    note: String,
    expected: String,
    suggest: Option<String>,
}

fn check(path: &Path) -> io::Result<Report> {
    let mut f = File::open(path)?;
    let mut head = Vec::new();
    (&mut f).take(4096).read_to_end(&mut head)?;
    let kind = detect(&head);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    let exp = expected(&ext);
    let expected_desc = match exp {
        Some(k) => k.iter().map(|x| format!("{:?}", x)).collect::<Vec<_>>().join(" o "),
        None => "?".to_string(),
    };

    // refinamiento segun el tipo detectado
    let mut note = String::new();
    let mut warn = false;
    let suggest: Option<String>;
    match kind {
        Kind::Pe => {
            let g = pe_detail(&mut f);
            if let Some(g) = g {
                note = format!("PE tipo {g}");
                warn = match ext.as_str() {
                    "exe" | "scr" => g == "dll",
                    "dll" | "ocx" => g != "dll",
                    _ => false,
                };
            }
            suggest = Some(g.unwrap_or("exe").to_string());
        }
        Kind::Zip => {
            let mut s = "zip";
            if let Some(names) = zip_names(&mut f) {
                if let Some(g) = zip_guess(&names) {
                    note = format!("zip con estructura de {}", g[0]);
                    warn = ZIP_FAMILY.contains(&ext.as_str()) && !g.contains(&ext.as_str());
                    s = g[0];
                }
            }
            suggest = Some(s.to_string());
        }
        Kind::Unknown => {
            let (d, s) = text_guess(&head);
            note = d.to_string();
            suggest = s.map(String::from);
        }
        other => suggest = kind_ext(other).map(String::from),
    }

    let verdict = match exp {
        None => {
            // extension rara: lo unico grave es que sea un ejecutable disfrazado
            if kind.is_executable() {
                Verdict::Mismatch { high: true }
            } else {
                Verdict::UnknownExt
            }
        }
        Some(ok) if ok.contains(&kind) => {
            if warn {
                Verdict::Warn
            } else {
                Verdict::Ok
            }
        }
        Some(_) => Verdict::Mismatch { high: kind.is_executable() },
    };

    Ok(Report { kind, verdict, note, expected: expected_desc, suggest })
}

fn walk(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        if let Ok(rd) = fs::read_dir(path) {
            for entry in rd.flatten() {
                walk(&entry.path(), out);
            }
        }
    } else if path.is_file() {
        out.push(path.to_path_buf());
    }
}

/// Separa la linea pegada/arrastrada en rutas. Windows entrecomilla las rutas con espacios.
fn parse_paths(line: &str) -> Vec<String> {
    let line = line.trim();
    if !line.contains('"') {
        return if line.is_empty() { vec![] } else { vec![line.to_string()] };
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in line.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                if !in_quote && !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn run() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();

    // doble clic en el .exe: pedir la ruta en vez de cerrarse
    if args.is_empty() && launched_from_explorer() {
        println!("Arrastra aqui un archivo o carpeta y presiona Enter:");
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        args = parse_paths(&line);
    }

    if args.is_empty() {
        eprintln!("Uso: extcheck <archivo|carpeta> [mas rutas...]");
        return ExitCode::from(2);
    }

    let mut files = Vec::new();
    for a in &args {
        walk(Path::new(a), &mut files);
    }

    let (mut total, mut bad, mut warns) = (0usize, 0usize, 0usize);
    for f in &files {
        total += 1;
        match check(f) {
            Ok(r) => {
                let mut detail = if r.note.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", r.note)
                };
                if let Some(s) = &r.suggest {
                    detail.push_str(&format!(" -> extension probable: .{s}"));
                }
                match r.verdict {
                    Verdict::Mismatch { high } => {
                        bad += 1;
                        let tag = if high { "ALERTA" } else { "MISMATCH" };
                        println!(
                            "[{tag}] {} -> esperado: {}, real: {:?}{detail}",
                            f.display(),
                            r.expected,
                            r.kind
                        );
                    }
                    Verdict::Warn => {
                        warns += 1;
                        println!(
                            "[AVISO] {} -> la firma cuadra, pero el contenido sugiere otra extension{detail}",
                            f.display()
                        );
                    }
                    Verdict::Ok | Verdict::UnknownExt => {}
                }
            }
            Err(e) => eprintln!("[ERR] {}: {e}", f.display()),
        }
    }

    println!("\n{total} archivos revisados, {bad} sospechosos, {warns} avisos");
    if bad > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS }
}

fn main() -> ExitCode {
    let code = run();
    if launched_from_explorer() {
        println!("\nPresiona Enter para salir...");
        let _ = io::stdin().read(&mut [0u8]);
    }
    code
}
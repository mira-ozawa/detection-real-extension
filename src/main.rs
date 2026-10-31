// extcheck: detecta si la extension de un archivo coincide con su contenido real (magic bytes).
// Uso: extcheck <archivo|carpeta> [mas rutas...]
// Sin dependencias externas, solo std.

use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
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

enum Verdict {
    Ok,
    Mismatch { high: bool },
    UnknownExt,
}

fn check(path: &Path) -> std::io::Result<(Kind, Verdict)> {
    let mut buf = [0u8; 16];
    let n = File::open(path)?.read(&mut buf)?;
    let kind = detect(&buf[..n]);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    let verdict = match expected(&ext) {
        None => {
            // extension rara: lo unico grave es que sea un ejecutable disfrazado
            if kind.is_executable() {
                Verdict::Mismatch { high: true }
            } else {
                Verdict::UnknownExt
            }
        }
        Some(ok) if ok.contains(&kind) => Verdict::Ok,
        Some(_) => Verdict::Mismatch { high: kind.is_executable() },
    };
    Ok((kind, verdict))
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

fn run() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() && launched_from_explorer() {
        println!("Arrastra aqui un archivo o carpeta y presiona Enter:");
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        let p = line.trim().trim_matches('"').to_string();
        if !p.is_empty() {
            args.push(p);
        }
    }

    if args.is_empty() {
        eprintln!("Uso: extcheck <archivo|carpeta> [mas rutas...]");
        return ExitCode::from(2);
    }

    let mut files = Vec::new();
    for a in &args {
        walk(Path::new(a), &mut files);
    }

    let (mut total, mut bad) = (0usize, 0usize);
    for f in &files {
        total += 1;
        match check(f) {
            Ok((kind, Verdict::Mismatch { high })) => {
                bad += 1;
                let tag = if high { "ALERTA" } else { "MISMATCH" };
                println!("[{tag}] {} -> contenido real: {:?}", f.display(), kind);
            }
            Ok((_, Verdict::Ok)) => {}
            Ok((_, Verdict::UnknownExt)) => {}
            Err(e) => eprintln!("[ERR] {}: {e}", f.display()),
        }
    }

    println!("\n{total} archivos revisados, {bad} sospechosos");
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
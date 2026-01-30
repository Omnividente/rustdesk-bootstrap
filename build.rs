use std::{
    env, fs,
    path::{Path, PathBuf},
    ffi::OsStr,
    io::Write,
};

fn main() {
    // Конфиг: берем локальный (не в репо) или пример
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let cfg_local = manifest_dir.join("config.local.rs");
    let cfg_example = manifest_dir.join("config.example.rs");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_cfg = out_dir.join("config.rs");

    println!("cargo:rerun-if-changed={}", cfg_local.display());
    println!("cargo:rerun-if-changed={}", cfg_example.display());

    let cfg_src = if cfg_local.exists() {
        cfg_local
    } else {
        println!("cargo:warning=Using config.example.rs (create config.local.rs with real values)");
        cfg_example
    };
    if let Err(e) = fs::copy(&cfg_src, &out_cfg) {
        panic!("failed to generate config.rs from {}: {}", cfg_src.display(), e);
    }

    // Следить за изменениями исходников ресурсов
    println!("cargo:rerun-if-changed=assets/bootstrap.ico");
    println!("cargo:rerun-if-changed=assets/app.manifest");

    // Пути проекта
    let assets_dir   = manifest_dir.join("assets");
    let icon_path    = assets_dir.join("bootstrap.ico");
    let mani_path    = assets_dir.join("app.manifest");

    // Если чего-то нет — пропустим вшивание, но сборку не валим
    if !icon_path.exists() || !mani_path.exists() {
        println!("cargo:warning=No icon/manifest: {} | {} — skipping embedding",
                 icon_path.display(), mani_path.display());
        return;
    }

    // Сгенерируем временный RC c абсолютными путями (windres любит абсолютные пути)
    let gen_rc  = out_dir.join("resources_autogen.rc");
    let mut rc  = fs::File::create(&gen_rc).expect("create rc");
    // 24 = RT_MANIFEST
    writeln!(rc, "1 ICON \"{}\"",   escape_backslashes(&icon_path)).unwrap();
    writeln!(rc, "1 24  \"{}\"",    escape_backslashes(&mani_path)).unwrap();

    // Попробуем автоматически найти инструмент ресурсов
    let target = env::var("TARGET").unwrap_or_default();
    let is_x64 = target.starts_with("x86_64");

    let mut candidates: Vec<PathBuf> = Vec::new();
    // 1) Твой путь
    let llvm_bin = PathBuf::from(r"C:\llvm-mingw\bin");
    if llvm_bin.is_dir() {
        candidates.push(llvm_bin.join("windres.exe"));
        candidates.push(llvm_bin.join(if is_x64 {
            "x86_64-w64-mingw32-windres.exe"
        } else {
            "i686-w64-mingw32-windres.exe"
        }));
        candidates.push(llvm_bin.join("llvm-rc.exe"));
    }
    // 2) LLVM стандартные
    for base in &[
        r"C:\Program Files\LLVM\bin",
        r"C:\Program Files (x86)\LLVM\bin",
    ] {
        let b = PathBuf::from(base);
        if b.is_dir() {
            candidates.push(b.join("llvm-rc.exe"));
            candidates.push(b.join("windres.exe"));
        }
    }
    // 3) Windows SDK rc.exe (для MSVC-сборок)
    for base in &[
        r"C:\Program Files (x86)\Windows Kits\10\bin",
        r"C:\Program Files (x86)\Windows Kits\8.1\bin",
    ] {
        let b = PathBuf::from(base);
        if b.is_dir() {
            if let Ok(entries) = fs::read_dir(&b) {
                let mut vers: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
                vers.sort(); vers.reverse();
                for v in vers {
                    let rc = if is_x64 { v.join("x64").join("rc.exe") } else { v.join("x86").join("rc.exe") };
                    candidates.push(rc);
                }
            }
        }
    }
    // 4) PATH
    if let Some(p) = where_first("windres.exe") { candidates.push(p); }
    if let Some(p) = where_first("llvm-rc.exe") { candidates.push(p); }
    if let Some(p) = where_first("rc.exe")      { candidates.push(p); }

    // Выбираем первый существующий
    if let Some(tool) = candidates.into_iter().find(|p| p.exists()) {
        let exe = tool.to_string_lossy().to_string();
        if exe.to_lowercase().contains("windres") {
            env::set_var("WINDRES", &exe);
            println!("cargo:warning=Using WINDRES: {}", exe);
        } else {
            env::set_var("RC", &exe);
            println!("cargo:warning=Using RC: {}", exe);
        }
        // Пустые макросы для embed-resource 2.x
        let empty: [&OsStr; 0] = [];
        if let Err(e) = std::panic::catch_unwind(|| {
            embed_resource::compile(&gen_rc, &empty);
        }) {
            println!("cargo:warning=embed-resource failed ({}): {:?}", exe, e);
        }
    } else {
        println!("cargo:warning=No windres/rc found — skipping resources embedding");
    }
}

fn escape_backslashes(p: &Path) -> String {
    // windres понимает и прямые, и экранированные обратные слэши
    // на всякий случай экранируем обратные
    p.display().to_string().replace('\\', "\\\\")
}

fn where_first(name: &str) -> Option<PathBuf> {
    std::process::Command::new("where")
        .arg(name)
        .output()
        .ok()
        .and_then(|o| {
            if !o.status.success() { return None; }
            let out = String::from_utf8_lossy(&o.stdout);
            out.lines().next().map(|s| PathBuf::from(s.trim()))
        })
}

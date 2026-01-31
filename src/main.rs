// src/main.rs.

use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use core::ffi::c_void;
use regex::Regex;
use crate::win_handle_helpers::{is_null, null};


// WinAPI.
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, WinBuiltinAdministratorsSid,
    TOKEN_ELEVATION, TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::Console::{
    GetConsoleScreenBufferInfo, GetStdHandle, SetConsoleTextAttribute,
    CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    FOREGROUND_BLUE, FOREGROUND_GREEN, FOREGROUND_INTENSITY, FOREGROUND_RED,
};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};

/* ===================== ВАЖНО ===================== */
// Все данные сервера и пароли вынесены в локальный конфиг.
// См. config.example.rs и README.md.
mod config { include!(concat!(env!("OUT_DIR"), "/config.rs")); }
use config::{HBBS, KEY, RELAY, PERM_PASSWORD};
// Папка логов.
const LOG_DIR: &str = r"C:\ProgramData\RustDeskDeploy\logs";
// Размер буфера SID.
const SECURITY_MAX_SID_SIZE: u32 = 68;
/* ================================================= */
// --- Win7 fallback: убрать импорт kernel32!GetSystemTimePreciseAsFileTime ---
#[cfg(all(target_os = "windows", target_env = "gnu"))]
mod win7_compat {
    use windows_sys::Win32::Foundation::FILETIME;

    // Стандартный GetSystemTimeAsFileTime доступен даже на WinXP/7.
    #[link(name = "kernel32")]
    extern "system" { fn GetSystemTimeAsFileTime(ft: *mut FILETIME); }

    // Делаем ту же сигнатуру и имя, что у точной версии.
    // Линковщик возьмет символ из этого объекта, поэтому внешний импорт не появится.
    #[no_mangle]
    pub extern "system" fn GetSystemTimePreciseAsFileTime(ft: *mut FILETIME) {
        unsafe { GetSystemTimeAsFileTime(ft) }
    }
}
// ---------------------------------------------------------------------------
#[cfg(all(windows, target_env = "gnu"))]
mod win_handle_helpers {
    use windows_sys::Win32::Foundation::HANDLE;

    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize;

    #[inline]
    pub fn is_null(h: HANDLE) -> bool {
        h == 0 || h == INVALID_HANDLE_VALUE
    }

    #[inline]
    pub fn null() -> HANDLE {
        0
    }
}
// --- Win7 fallback: убрать импорт ws2_32!GetHostNameW ------------------------
#[cfg(all(target_os = "windows", target_env = "gnu"))]
mod win7_net_compat {
    use windows_sys::Win32::Foundation::BOOL;

    // Имя компьютера получаем через Kernel32 (доступно в Win7).
    #[link(name = "kernel32")]
    extern "system" {
        fn GetComputerNameW(lpBuffer: *mut u16, nSize: *mut u32) -> BOOL;
    }

    const SOCKET_ERROR: i32 = -1;

    /// Подпись совпадает с ws2_32!GetHostNameW, но реализация своя (через GetComputerNameW).
    /// Это убирает импорт из ws2_32 и позволяет запускаться на Win7.
    #[no_mangle]
    pub extern "system" fn GetHostNameW(name: *mut u16, namelen: i32) -> i32 {
        if name.is_null() || namelen <= 0 {
            return SOCKET_ERROR;
        }
        let mut size: u32 = namelen as u32; // размер буфера в WCHAR'ах
        unsafe {
            if GetComputerNameW(name, &mut size) != 0 {
                // На случай, если останется место, допишем терминатор.
                if (size as i32) < namelen {
                    *name.add(size as usize) = 0;
                }
                0
            } else {
                SOCKET_ERROR
            }
        }
    }
}
// === Win7 shim для api-ms-win-core-synch-l1-2-0 ===
// Исключаем импорт WaitOnAddress / WakeByAddress* (Win8+), чтобы EXE запускался на Win7.
#[cfg(all(target_os = "windows", target_env = "gnu"))]
mod win7_synch_compat {
    use core::{ptr, ffi::c_void};
    use windows_sys::Win32::Foundation::BOOL;

    #[link(name = "kernel32")]
    extern "system" {
        fn Sleep(ms: u32);
        fn GetTickCount() -> u32;
    }

    #[inline]
    unsafe fn mem_eq_volatile(a: *const u8, b: *const u8, len: usize) -> bool {
        // Аккуратное сравнение байтов (volatile), чтобы не допустить лишних оптимизаций.
        for i in 0..len {
            let va = ptr::read_volatile(a.add(i));
            let vb = ptr::read_volatile(b.add(i));
            if va != vb { return false; }
        }
        true
    }

    /// Подпись соответствует WinAPI:
    /// BOOL WaitOnAddress(volatile VOID* Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds)
    #[no_mangle]
    pub extern "system" fn WaitOnAddress(addr: *const c_void, cmp: *const c_void, size: usize, ms: u32) -> BOOL {
        // При некорректных параметрах ведем себя как WinAPI: считаем, что ожидание не завершилось.
        if addr.is_null() || cmp.is_null() || size == 0 {
            return 0; // FALSE
        }

        // INFINITE = 0xFFFFFFFF.
        let infinite = ms == 0xFFFF_FFFF;
        let start = unsafe { GetTickCount() };

        loop {
            // Выходим, если значение изменилось.
            let equal = unsafe { mem_eq_volatile(addr as *const u8, cmp as *const u8, size) };
            if !equal {
                return 1; // TRUE - "адрес изменился"
            }

            // Проверим таймаут, если он задан.
            if !infinite {
                let now = unsafe { GetTickCount() };
                // Простая арифметика по модулю 2^32, как у GetTickCount().
                if now.wrapping_sub(start) >= ms {
                    return 0; // FALSE - таймаут
                }
            }

            // Короткая пауза, чтобы не перегружать CPU.
            unsafe { Sleep(1); }
        }
    }

    /// VOID WakeByAddressAll(PVOID Address)
    #[no_mangle]
    pub extern "system" fn WakeByAddressAll(_: *const c_void) {
        // Ничего не требуется. WaitOnAddress сам опрашивает значение.
    }

    /// VOID WakeByAddressSingle(PVOID Address)
    #[no_mangle]
    pub extern "system" fn WakeByAddressSingle(_: *const c_void) {
        // Ничего не требуется.
    }
}
// === Win7 shim для bcryptprimitives!ProcessPrng (Win8+) ======================
#[cfg(all(target_os = "windows", target_env = "gnu"))]
mod win7_prng_compat {
    use core::ffi::c_void;

    // Win7-совместимый генератор: advapi32!SystemFunction036 (RtlGenRandom).
    // BOOLEAN SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength).
    #[link(name = "advapi32")]
    extern "system" {
        fn SystemFunction036(buf: *mut c_void, len: u32) -> i32;
    }

    /// Сигнатура ProcessPrng в mingw-w64 фактически (void*, size_t). На x64 Windows
    /// соглашение вызова единое, поэтому extern "system" безопасен.
    /// Делаем ту же точку входа, чтобы линковщик не создавал импорт из bcryptprimitives.dll.
    #[no_mangle]
    pub extern "system" fn ProcessPrng(buf: *mut c_void, len: usize) {
        unsafe {
            let _ = SystemFunction036(buf, len as u32);
        }
    }
}
 
// =============================================================================
// ---------- WinHTTP (Win7+) ----------

// --- Универсальная обертка: пробуем WinHTTP, при ошибке используем rustls/reqwest. ---
fn winhttp_request(method: &str, url: &str, extra_headers: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    match winhttp_request_winhttp(method, url, extra_headers) {
        Ok(bytes) => Ok(bytes),
        Err(_e) => {
            // Частая ситуация на Win7: ERROR_WINHTTP_SECURE_FAILURE (12175) и др.
            
            use reqwest::blocking::Client;
            use reqwest::Method as RM;

            let m = match method { "POST" => RM::POST, "HEAD" => RM::HEAD, _ => RM::GET };
            let client = Client::builder()
                .user_agent("curl/8.0")
                .build()
                .map_err(|er| format!("reqwest build: {er}"))?;

            let mut req = client.request(m, url);
            for (k, v) in extra_headers { req = req.header(*k, *v); }

            let resp = req.send().map_err(|er| format!("reqwest send: {er}"))?;
            let body = resp.bytes().map_err(|er| format!("reqwest body: {er}"))?;
            Ok(body.to_vec())
        }
    }
}

// --- "Чистый" WinHTTP без резервного варианта. Возвращает Err(...) с gle и host/port. ---
fn winhttp_request_winhttp(method: &str, url: &str, extra_headers: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    use std::{mem, ptr};

    const INTERNET_SCHEME_HTTPS: u32 = 2;
    const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;

    #[inline]
    fn wide_z(s: &str) -> Vec<u16> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }
    #[inline]
    fn u16z_to_string(buf: &[u16]) -> String {
        let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..nul])
    }

    let wurl = wide_z(url);

    // 1) сессия: DEFAULT_PROXY
    let mut h_session = unsafe {
        windows_sys::Win32::Networking::WinHttp::WinHttpOpen(
            wide_z("rustdesk-bootstrap").as_ptr(),
            windows_sys::Win32::Networking::WinHttp::WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            ptr::null(), ptr::null(), 0,
        )
    };
    if h_session.is_null() {
        return Err(format!("WinHttpOpen (gle={})",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }));
    }

    // 2) разбор URL в собственные буферы
    let mut uc: windows_sys::Win32::Networking::WinHttp::URL_COMPONENTS = unsafe { mem::zeroed() };
    uc.dwStructSize = mem::size_of::<windows_sys::Win32::Networking::WinHttp::URL_COMPONENTS>() as u32;

    let mut host_buf  = vec![0u16; 256];
    let mut path_buf  = vec![0u16; 2048];
    let mut extra_buf = vec![0u16; 1024];
    uc.lpszHostName = host_buf.as_mut_ptr();   uc.dwHostNameLength  = host_buf.len()  as u32;
    uc.lpszUrlPath  = path_buf.as_mut_ptr();   uc.dwUrlPathLength   = path_buf.len()  as u32;
    uc.lpszExtraInfo= extra_buf.as_mut_ptr();  uc.dwExtraInfoLength = extra_buf.len() as u32;

    if unsafe { windows_sys::Win32::Networking::WinHttp::WinHttpCrackUrl(wurl.as_ptr(), 0, 0, &mut uc) } == 0 {
        unsafe { windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session) };
        return Err(format!("WinHttpCrackUrl (gle={})",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }));
    }

    let host = u16z_to_string(&host_buf);
    if host.is_empty() {
        unsafe { windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session) };
        return Err("WinHttpConnect: empty host".into());
    }
    let mut path = u16z_to_string(&path_buf);
    let extra    = u16z_to_string(&extra_buf);
    if path.is_empty() { path.push('/'); }
    if !extra.is_empty() { path.push_str(&extra); }

    let is_https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    let port: u16 = if uc.nPort != 0 { uc.nPort } else if is_https { 443 } else { 80 };

    let host_w = wide_z(&host);
    let path_w = wide_z(&path);

    // 3) подключение; при ошибке используем DIRECT
    let mut h_connect = unsafe {
        windows_sys::Win32::Networking::WinHttp::WinHttpConnect(h_session, host_w.as_ptr(), port, 0)
    };
    if h_connect.is_null() {
        unsafe { windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session) };
        h_session = unsafe {
            windows_sys::Win32::Networking::WinHttp::WinHttpOpen(
                wide_z("rustdesk-bootstrap").as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY, ptr::null(), ptr::null(), 0,
            )
        };
        if h_session.is_null() {
            return Err(format!("WinHttpOpen(no-proxy) (gle={})",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }));
        }
        h_connect = unsafe {
            windows_sys::Win32::Networking::WinHttp::WinHttpConnect(h_session, host_w.as_ptr(), port, 0)
        };
        if h_connect.is_null() {
            let gle = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            unsafe { windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session) };
            return Err(format!("WinHttpConnect (gle={}; host={}; port={})", gle, host, port));
        }
    }

    // 4) запрос
    let flags = if is_https { windows_sys::Win32::Networking::WinHttp::WINHTTP_FLAG_SECURE } else { 0 };
    let h_req = unsafe {
        windows_sys::Win32::Networking::WinHttp::WinHttpOpenRequest(
            h_connect, wide_z(method).as_ptr(), path_w.as_ptr(),
            ptr::null(), ptr::null(), ptr::null_mut(), flags,
        )
    };
    if h_req.is_null() {
        let gle = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        unsafe {
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_connect);
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session);
        }
        return Err(format!("WinHttpOpenRequest (gle={})", gle));
    }

    // 5) TLS 1.0/1.1/1.2
    let mut prot: u32 = 0x00000080 | 0x00000200 | 0x00000800;
    let _ = unsafe {
        windows_sys::Win32::Networking::WinHttp::WinHttpSetOption(
            h_req,
            windows_sys::Win32::Networking::WinHttp::WINHTTP_OPTION_SECURE_PROTOCOLS,
            &mut prot as *mut _ as _, mem::size_of::<u32>() as u32,
        )
    };

    // 6) заголовки
    let mut headers = String::from("User-Agent: curl/8.0\r\nAccept: */*\r\n");
    for (k, v) in extra_headers { headers.push_str(&format!("{}: {}\r\n", k, v)); }
    unsafe {
        windows_sys::Win32::Networking::WinHttp::WinHttpAddRequestHeaders(
            h_req, wide_z(&headers).as_ptr(), u32::MAX,
            windows_sys::Win32::Networking::WinHttp::WINHTTP_ADDREQ_FLAG_ADD
            | windows_sys::Win32::Networking::WinHttp::WINHTTP_ADDREQ_FLAG_REPLACE,
        );
    }

    // 7) отправка и прием
    if unsafe {
        windows_sys::Win32::Networking::WinHttp::WinHttpSendRequest(
            h_req, ptr::null(), 0, ptr::null_mut(), 0, 0, 0
        )
    } == 0 {
        let gle = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        unsafe {
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_req);
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_connect);
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session);
        }
        return Err(format!("WinHttpSendRequest (gle={})", gle));
    }

    if unsafe { windows_sys::Win32::Networking::WinHttp::WinHttpReceiveResponse(h_req, ptr::null_mut()) } == 0 {
        let gle = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        unsafe {
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_req);
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_connect);
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session);
        }
        return Err(format!("WinHttpReceiveResponse (gle={})", gle));
    }

    // 8) тело
    let mut out = Vec::new();
    loop {
        let mut avail: u32 = 0;
        if unsafe { windows_sys::Win32::Networking::WinHttp::WinHttpQueryDataAvailable(h_req, &mut avail) } == 0
            || avail == 0 { break; }
        let mut chunk = vec![0u8; avail as usize];
        let mut read: u32 = 0;
        if unsafe {
            windows_sys::Win32::Networking::WinHttp::WinHttpReadData(h_req, chunk.as_mut_ptr() as _, avail, &mut read)
        } == 0 { break; }
        out.extend_from_slice(&chunk[..read as usize]);
    }

    unsafe {
        windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_req);
        windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_connect);
        windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(h_session);
    }
    Ok(out)
}





fn http_get_string(url: &str) -> Result<String, String> {
    let b = winhttp_request("GET", url, &[("Accept","application/json")])?;
    Ok(String::from_utf8_lossy(&b).to_string())
}

fn http_download(url: &str, dest: &std::path::Path) -> Result<(), String> {
    let b = winhttp_request("GET", url, &[])?;
    let tmp = dest.with_extension("part");
    std::fs::write(&tmp, &b).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dest).map_err(|e| e.to_string())?;
    Ok(())
}

// -----------------------------------------------------------------------------

/* ---------- Цветной вывод в консоль + запись в лог ---------- */
#[derive(Clone, Copy)]
enum Lvl { Step, #[allow(dead_code)] Info, Ok, Warn, Err }
fn lvl_tag(l: Lvl) -> &'static str {
    match l { Lvl::Step=>"STEP", Lvl::Info=>"INFO", Lvl::Ok=>"OK", Lvl::Warn=>"WARN", Lvl::Err=>"ERROR" }
}
fn lvl_color(l: Lvl) -> u16 {
    match l {
        Lvl::Step => FOREGROUND_GREEN | FOREGROUND_BLUE  | FOREGROUND_INTENSITY, // cyan
        Lvl::Info => FOREGROUND_BLUE  | FOREGROUND_INTENSITY,                    // bright blue
        Lvl::Ok   => FOREGROUND_GREEN | FOREGROUND_INTENSITY,                    // bright green
        Lvl::Warn => FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY, // yellow
        Lvl::Err  => FOREGROUND_RED   | FOREGROUND_INTENSITY,                    // bright red
    }
}
fn print_colored(line: &str, l: Lvl) {
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if is_null(h) { println!("{}", line); return; }
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(h, &mut info) == 0 { println!("{}", line); return; }
        let orig = info.wAttributes;
        let _ = SetConsoleTextAttribute(h, lvl_color(l));
        println!("{}", line);
        let _ = SetConsoleTextAttribute(h, orig);
    }
}

#[derive(Default)]
struct LogState {
    step_current: u32,
    step_total: u32,
    pending_step: bool,
    last_step_started: Option<Instant>,
}

fn log_state() -> &'static Mutex<LogState> {
    static STATE: OnceLock<Mutex<LogState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(LogState::default()))
}

fn log_set_total_steps(total: u32) {
    let mut st = log_state().lock().unwrap();
    st.step_total = total;
    st.step_current = 0;
    st.pending_step = false;
    st.last_step_started = None;
}

fn fmt_duration(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

fn step_tag(console: bool, step: u32, total: u32) -> String {
    let label = if console { "ШАГ" } else { "STEP" };
    if total > 0 {
        format!("{} {}/{}", label, step, total)
    } else {
        format!("{} {}", label, step)
    }
}

fn log_file_line(log: &mut fs::File, tag: &str, msg: &str) {
    let _ = writeln!(log, "{} [{}] {}", now_log_ts(), tag, msg);
}

fn log_file_info(log: &mut fs::File, msg: &str) {
    log_file_line(log, "INFO", msg);
}

fn log_file_warn(log: &mut fs::File, msg: &str) {
    log_file_line(log, "WARN", msg);
}

fn log_file_err(log: &mut fs::File, msg: &str) {
    log_file_line(log, "ERROR", msg);
}

fn log_step(log: &mut fs::File, msg: &str) {
    let (prev_step_no, prev_elapsed, step_no, step_total) = {
        let mut st = log_state().lock().unwrap();
        let prev_elapsed = if st.pending_step {
            st.last_step_started.map(|t| t.elapsed())
        } else {
            None
        };
        let prev_step_no = st.step_current;
        st.step_current = st.step_current.saturating_add(1);
        st.pending_step = true;
        st.last_step_started = Some(Instant::now());
        (prev_step_no, prev_elapsed, st.step_current, st.step_total)
    };

    // Если предыдущий шаг не был закрыт, закрываем его только в файле.
    if let Some(elapsed) = prev_elapsed {
        let tag = step_tag(false, prev_step_no.max(1), step_total);
        log_file_line(log, &tag, &format!("done ({})", fmt_duration(elapsed)));
    }

    let tag_console = step_tag(true, step_no, step_total);
    let tag_file = step_tag(false, step_no, step_total);
    print_colored(&format!("[{}] {}", tag_console, msg), Lvl::Step);
    log_file_line(log, &tag_file, msg);
}

fn log_event(log: &mut fs::File, lvl: Lvl, msg: &str) {
    match lvl {
        Lvl::Step => log_step(log, msg),
        Lvl::Info => log_file_info(log, msg),
        _ => {
            let mut suffix = String::new();
            if matches!(lvl, Lvl::Ok | Lvl::Warn | Lvl::Err) {
                let mut st = log_state().lock().unwrap();
                if st.pending_step {
                    if let Some(start) = st.last_step_started.take() {
                        suffix = format!(" ({})", fmt_duration(start.elapsed()));
                    }
                    st.pending_step = false;
                }
            }
            let tag = lvl_tag(lvl);
            let console_line = if suffix.is_empty() {
                format!("[{}] {}", tag, msg)
            } else {
                format!("[{}] {}{}", tag, msg, suffix)
            };
            print_colored(&console_line, lvl);

            let file_msg = if suffix.is_empty() {
                msg.to_string()
            } else {
                format!("{}{}", msg, suffix)
            };
            log_file_line(log, tag, &file_msg);
        }
    }
}

macro_rules! logline {
    ($log:expr, $lvl:expr, $($arg:tt)*) => {{
        let msg = format!($($arg)*);
        log_event($log, $lvl, &msg);
    }};
}

// Крупные шаги и итоги: в файл и в консоль (с цветами).
macro_rules! STEP { ($log:expr, $($arg:tt)*) => { logline!($log, Lvl::Step, $($arg)*) } }
macro_rules! OK   { ($log:expr, $($arg:tt)*) => { logline!($log, Lvl::Ok,   $($arg)*) } }
macro_rules! WARN { ($log:expr, $($arg:tt)*) => { logline!($log, Lvl::Warn, $($arg)*) } }
macro_rules! ERR  { ($log:expr, $($arg:tt)*) => { logline!($log, Lvl::Err,  $($arg)*) } }

// INFO - только в лог-файл (в консоль ничего).
macro_rules! INFO {
    ($log:expr, $($arg:tt)*) => {{
        // Пишем вручную строку в файл, не вызывая logline! (чтобы не было вывода в консоль).
        log_file_info($log, &format!($($arg)*));
    }};
}

// (Если в коде встречается ERROR!, оставляем алиас.)
#[allow(unused_macros)]
macro_rules! ERROR { ($($t:tt)*) => { ERR!($($t)*); } }

fn get_service_binpath(name: &str) -> Option<PathBuf> {
    // sc qc <name> -> строка "BINARY_PATH_NAME : <path> [args]".
    let out = Command::new("sc.exe").args(&["qc", name]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(rest) = line.trim().strip_prefix("BINARY_PATH_NAME") {
            let path_part = rest.splitn(2, ':').nth(1)?.trim();
            let unquoted = path_part.trim_matches('"');
            let exe_str = unquoted.split(" --").next().unwrap_or(unquoted).trim();
            return Some(PathBuf::from(exe_str));
        }
    }
    None
}

fn log_boot_header(
    log: &mut fs::File,
    already_installed: bool,
    local_installer: Option<&str>,
    force_x86: bool,
) {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "?".to_string());
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "?".to_string());
    let arch = if is_os_64bit() { "x64" } else { "x86" };

    log_file_info(log, "==============================");
    log_file_info(log, &format!("RustDesk Bootstrap v{}", env!("CARGO_PKG_VERSION")));
    log_file_info(log, &format!("Start: {}", now_log_ts()));
    log_file_info(log, &format!("User: {}  Host: {}  PID: {}", user, host, std::process::id()));
    log_file_info(log, &format!("OS: {}  Arch: {}  ForceX86: {}", os_version_string(), arch, force_x86));
    log_file_info(log, &format!("HBBS: {}", HBBS));
    log_file_info(log, &format!("Relay: {}", RELAY.unwrap_or("-")));
    log_file_info(log, &format!("PermPassword: {}", if PERM_PASSWORD.is_some() { "set" } else { "none" }));
    log_file_info(log, &format!("AlreadyInstalled: {}", already_installed));
    if let Some(p) = local_installer {
        log_file_info(log, &format!("LocalInstaller: {}", p));
    }
    log_file_info(log, "==============================");
}

/* --------------------------- MAIN --------------------------- */
fn main() {
    // Лог.
    let _ = fs::create_dir_all(LOG_DIR);
    let log_path = PathBuf::from(LOG_DIR).join(format!("rustdesk-bootstrap-{}.log", now_ymdhms()));
    let mut log = fs::File::create(&log_path).expect("open log");

    // Аргументы.
    let args: Vec<String> = std::env::args().collect();
    let mut local_installer: Option<String> = None;
    let mut force_x86 = false;
    let mut no_pause = false;
    for a in args.iter().skip(1) {
        if let Some(v) = a.strip_prefix("--local-installer=") { local_installer = Some(v.trim_matches('"').to_string()); }
        else if a == "--force-x86" { force_x86 = true; }
        else if a == "--no-pause" || a == "--silent" || a == "--quiet" { no_pause = true; }
    }
    let overall_start = Instant::now();
    // UAC.
    if !is_elevated() {
        WARN!(&mut log, "Требуются права администратора. Перезапускаю...");
        relaunch_as_admin();
        return;
    }

    // Определяем, установлен ли уже RustDesk (нужно для расчета шагов).
    let already_installed = find_rustdesk_exe().is_some();
    let total_steps = 7 + if PERM_PASSWORD.is_some() { 1 } else { 0 };
    log_set_total_steps(total_steps);
    log_boot_header(&mut log, already_installed, local_installer.as_deref(), force_x86);

    // Проверка системы.
    STEP!(&mut log, "Проверка системы");
    let is64 = is_os_64bit() && !force_x86;
    OK!(&mut log, "Архитектура: {}", if is64 { "x64" } else { "x86" });

    // Получение установщика (Win7-safe).
    STEP!(&mut log, "Получение установщика");
    let (installer_path, asset_type, tag) = match local_installer.clone() {
        Some(p) => {
            INFO!(&mut log, "Использую локальный инсталлятор: {}", p);
            (PathBuf::from(&p),
             if p.to_lowercase().ends_with(".msi") { "msi".to_string() } else { "exe".to_string() },
             extract_version_from_name(&p).unwrap_or_else(|| "(unknown)".into()))
        }
        None => {
            let (url, kind, ver) = fetch_latest_asset(is64, &mut log)
                .unwrap_or_else(|e| fatal(&log_path, &mut log, &format!("latest asset: {e}")));
            let dest = std::env::temp_dir().join(file_name_from_url(&url));
            INFO!(&mut log, "Выбран: {} [{}] Версия: {}", dest.file_name().unwrap().to_string_lossy(), &kind, &ver);
            INFO!(&mut log, "Скачиваю {}", url);
            http_download(&url, &dest)
                .unwrap_or_else(|e| fatal(&log_path, &mut log, &format!("download {}: {}", url, e)));
            (dest, kind, ver)
        }
    };
    OK!(&mut log, "Установщик: {} [{}] {}", installer_path.file_name().unwrap_or_default().to_string_lossy(), asset_type, tag);

    // Подготовка перед установкой.
    if !already_installed {
        STEP!(&mut log, "Предварительная настройка");
        match write_configs(&mut log) {
            Ok(_) => OK!(&mut log, "Конфиги подготовлены"),
            Err(e) => WARN!(&mut log, "Не удалось записать конфиги: {}", e),
        }
    } else {
        STEP!(&mut log, "Остановка службы и GUI");
        stop_service_and_processes(&mut log);
        OK!(&mut log, "Остановлено");
    }
    // Установка.
    STEP!(&mut log, "Установка");
    match asset_type.as_str() {
        "msi" => { install_msi(&installer_path, &mut log); }
        _     => { install_exe_with_timeout(&installer_path, &mut log); }
    }
    OK!(&mut log, "Установка завершена");
    // Подготовка службы.
    STEP!(&mut log, "Подготовка службы");
    // 1) Быстро проверяем, не зарегистрировалась ли служба.
    let svc_name_fast = wait_for_rustdesk_service(Duration::from_secs(10), &mut log);
    let rustexe = if let Some(ref svc) = svc_name_fast {
        if let Some(p) = get_service_binpath(svc) {
            INFO!(&mut log, "service {} -> {}", svc, p.display());
            p
        } else {
            // Служба есть, но путь не получен - ждем файл.
            wait_for_rustdesk_exe(Duration::from_secs(45), &mut log)
                .unwrap_or_else(|| fatal(&log_path, &mut log, "После установки не найден rustdesk.exe"))
        }
    } else {
        // Службы еще нет - ждем файл (сокращенный таймаут).
        wait_for_rustdesk_exe(Duration::from_secs(45), &mut log)
            .unwrap_or_else(|| fatal(&log_path, &mut log, "После установки не найден rustdesk.exe"))
    };

    // 2) Удостоверимся, что служба присутствует и в автозапуске.
    let mut svc_found = true;
    let svc_name = svc_name_fast
        .or_else(|| wait_for_rustdesk_service(Duration::from_secs(30), &mut log))
        .or_else(|| ensure_service_present_and_auto(&rustexe, &mut log))
        .unwrap_or_else(|| {
            svc_found = false;
            log_file_warn(&mut log, "Сервис не найден после установки");
            String::from("rustdesk")
        });
    if svc_found {
        OK!(&mut log, "Служба: {}", svc_name);
    } else {
        WARN!(&mut log, "Служба не найдена, использую {}", svc_name);
    }
    // Конфиги до первого старта.
    STEP!(&mut log, "Запись конфигов");
    write_configs(&mut log).unwrap_or_else(|e| fatal(&log_path, &mut log, &format!("write config: {e}")));
    OK!(&mut log, "Конфиги записаны");

    // Постоянный пароль.
    if let Some(pw) = PERM_PASSWORD {
        STEP!(&mut log, "Постоянный пароль");
        let ok = set_perm_password_safe(&rustexe, pw, &mut log);
        let synced = sync_user_config_to_service(&mut log);
        if ok {
            if synced {
                OK!(&mut log, "Пароль установлен");
            } else {
                WARN!(&mut log, "Пароль установлен, но конфиг не синхронизирован");
            }
        } else {
            WARN!(&mut log, "Не удалось установить пароль через CLI, см. лог");
        }
    }
    // Запуск службы (мягкий рестарт при RUNNING).
    STEP!(&mut log, "Запуск службы");
    restart_service_safely(&svc_name, &mut log);
    if get_service_state(&svc_name) != SvcState::Running {
        WARN!(&mut log, "Сервис не запустился ({}). Проверь Журнал Windows -> Система.", svc_name);
    } else {
        OK!(&mut log, "Сервис запущен: {}", svc_name);
    }

    // Итог.
    OK!(&mut log, "Готово за {:.1}s", overall_start.elapsed().as_secs_f64());
    OK!(&mut log, "RustDesk установлен и настроен.");
    OK!(&mut log, "Версия:   {}", tag);
    OK!(&mut log, "Бинарник: {}", rustexe.display());
    OK!(&mut log, "Лог:      {}", log_path.display());
    if let Some(id) = get_rustdesk_id(&rustexe, &mut log) {
        OK!(&mut log, "ID:       {}", id);
    } else {
        WARN!(&mut log, "ID:       не удалось получить");
    }
    if let Some(pw) = PERM_PASSWORD {
        OK!(&mut log, "Пароль:   {}", pw);
    } else {
        OK!(&mut log, "Пароль:   (не задан)");
    }

    if !no_pause {
        println!();
        println!("Нажмите Enter, чтобы закрыть окно...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}

/* ======================= HELPERS ======================= */

// Win7-safe timestamp для имени лога.
fn now_ymdhms() -> String {
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!("{:04}{:02}{:02}-{:02}{:02}{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond)
    }
}

fn now_log_ts() -> String {
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds)
    }
}

// Архитектура.
fn is_os_64bit() -> bool {
    std::env::var("PROCESSOR_ARCHITEW6432").is_ok()
        || std::env::var("PROCESSOR_ARCHITECTURE").map(|s| s.contains("64")).unwrap_or(false)
}



fn file_name_from_url(url: &str) -> String {
    let last = url.rsplit('/').next().unwrap_or("rustdesk-latest");
    last.split('?').next().unwrap_or(last).to_string()
}

fn http_get_string_via_certutil(url: &str, _log: &mut fs::File) -> Result<String, String> {
    // Certutil не используем, читаем напрямую через WinHTTP.
    http_get_string(url)
}




// ==== Timestamp без импорта std::time ====
fn ts_for_file() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

fn dump_html(
    prefix: &str,
    suffix: &str,
    html: &str,
    log_dir: &std::path::Path,
    log: &mut std::fs::File,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(log_dir)?;
    let name = if suffix.is_empty() {
        format!("{}-{}.html", prefix, ts_for_file())
    } else {
        format!("{}-{}-{}.html", prefix, suffix, ts_for_file())
    };
    let path = log_dir.join(name);
    std::fs::write(&path, html)?;
    INFO!(log, "dumped HTML: {}", path.display());
    Ok(path)
}


fn os_version_string() -> String {
    unsafe {
        let mut osvi: OSVERSIONINFOW = core::mem::zeroed();
        osvi.dwOSVersionInfoSize = core::mem::size_of::<OSVERSIONINFOW>() as u32;
        if GetVersionExW(&mut osvi) == 0 {
            return "unknown".to_string();
        }
        format!("{}.{} build {}", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber)
    }
}

fn is_windows_7() -> bool {
    unsafe {
        let mut osvi: OSVERSIONINFOW = core::mem::zeroed();
        osvi.dwOSVersionInfoSize = core::mem::size_of::<OSVERSIONINFOW>() as u32;
        if GetVersionExW(&mut osvi) == 0 { return false; }
        osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1 // 6.1 = Win7
    }
}
fn resolve_latest_tag_url_from_html(
    html: &str,
    log: &mut std::fs::File,
) -> Option<String> {
    // 1) Обычная ссылка на тег
    let re_tag_dq = regex::Regex::new(
        r#"href="(?P<href>(?:https://github\.com)?/rustdesk/rustdesk/releases/tag/v?\d+\.\d+\.\d+)""#
    ).unwrap();
    let re_tag_sq = regex::Regex::new(
        r#"href='(?P<href>(?:https://github\.com)?/rustdesk/rustdesk/releases/tag/v?\d+\.\d+\.\d+)'"#
    ).unwrap();

    if let Some(c) = re_tag_dq.captures(html).or_else(|| re_tag_sq.captures(html)) {
        let href = c.name("href").unwrap().as_str();
        let url = if href.starts_with("http") { href.to_string() }
                  else { format!("https://github.com{}", href) };
        INFO!(log, "latest -> tag via <a>: {}", url);
        return Some(url);
    }

    // 2) JSON: update_url
    let re_json_url = regex::Regex::new(
        r#""update_url"\s*:\s*"(?P<href>/rustdesk/rustdesk/releases/tag/v?\d+\.\d+\.\d+)""#
    ).unwrap();
    if let Some(c) = re_json_url.captures(html) {
        let href = c.name("href").unwrap().as_str();
        let url = format!("https://github.com{}", href);
        INFO!(log, "latest -> tag via JSON.update_url: {}", url);
        return Some(url);
    }

    // 3) JSON: tag_name -> попробуем сначала с 'v', потом без
    let re_json_tag = regex::Regex::new(
        r#""tag_name"\s*:\s*"(?P<ver>\d+\.\d+\.\d+)""#
    ).unwrap();
    if let Some(c) = re_json_tag.captures(html) {
        let ver = c.name("ver").unwrap().as_str();
        let url = format!("https://github.com/rustdesk/rustdesk/releases/tag/v{}", ver);
        INFO!(log, "latest -> tag via JSON.tag_name: {}", url);
        return Some(url);
    }

    None
}


// ==== Главная: выбор ассета ====
fn fetch_latest_asset(is64: bool, log: &mut std::fs::File) -> Result<(String, String, String), String> {
    INFO!(log, "GitHub Releases (latest): выбираю ассет");
    let log_dir = std::path::Path::new(LOG_DIR);

    let html_latest = http_get_string_via_certutil(
        "https://github.com/rustdesk/rustdesk/releases/latest", log
    )?;

    // Дамп страницы latest.
    let _ = dump_html("latest", "", &html_latest, log_dir, log);

    let archs64 = ["x86_64", "x64", "amd64"];
    let archs32 = ["x86", "i386", "i686"];
    let archs   = if is64 { &archs64[..] } else { &archs32[..] };
    let is_win7 = is_windows_7();

    // Регексы ассетов: учитываем " и ' (без обратных ссылок).
    
    let asset_re_dq = regex::Regex::new(
        r#"href="(?P<href>(?:https://github\.com)?/rustdesk/rustdesk/releases/download/(?P<tag>v?\d+\.\d+\.\d+)/rustdesk-(?P<ver>\d+\.\d+\.\d+)-(?P<arch>[A-Za-z0-9._-]+)\.(?P<ext>msi|exe)(?:\?[^"']*)?)""#
    ).unwrap();

    // Ранее (одинарные кавычки).
    // r#"href='(?P<href>(?:https://github\.com)?/rustdesk/rustdesk/releases/download/(?P<tag>v?\d+\.\d+\.\d+)/rustdesk-(?P<ver>\d+\.\d+\.\d+)-(?P<arch>[A-Za-z0-9._-]+)\.(?P<ext>msi|exe))'"#
    let asset_re_sq = regex::Regex::new(
        r#"href='(?P<href>(?:https://github\.com)?/rustdesk/rustdesk/releases/download/(?P<tag>v?\d+\.\d+\.\d+)/rustdesk-(?P<ver>\d+\.\d+\.\d+)-(?P<arch>[A-Za-z0-9._-]+)\.(?P<ext>msi|exe)(?:\?[^"']*)?)'"#
    ).unwrap();


    fn pick_from_html(
        html: &str,
        where_from: &str,
        is64: bool,
        is_win7: bool,
        archs: &[&str],
        regs: [&regex::Regex; 2],
        log: &mut std::fs::File,
    ) -> Option<(String, String, String)> {
        let mut sciter_x64: Option<(String, String, String)> = None;
        let mut sciter_x86: Option<(String, String, String)> = None;
        let mut msi:        Option<(String, String, String)> = None;
        let mut exe_plain:  Option<(String, String, String)> = None;

        for re in regs {
            for caps in re.captures_iter(html) {
                let href  = &caps["href"];
                let v_tag = caps["tag"].trim_start_matches('v');
                let v_fn  = &caps["ver"];
                let arch_full = caps["arch"].to_lowercase();
                let ext   = &caps["ext"];

                if v_tag != v_fn {
                    INFO!(log, "{}: skip {}: version mismatch tag={} file={}", where_from, ext, v_tag, v_fn);
                    continue;
                }

                // Фильтр архитектуры; на Win7 разрешаем x86-sciter на x64.
                let mut arch_ok = archs.iter().any(|a| arch_full.contains(a));
                let is_sciter_exe = ext == "exe" && arch_full.contains("sciter");
                if !arch_ok && is_win7 && is_sciter_exe {
                    arch_ok = true;
                }
                if !arch_ok {
                    INFO!(log, "{}: skip {}: arch mismatch ({})", where_from, ext, arch_full);
                    continue;
                }

                let url = if href.starts_with("http") { href.to_string() }
                          else { format!("https://github.com{}", href) };

                INFO!(log, "{}: asset hit: ext={}, arch={}, tag={}, url={}", where_from, ext, arch_full, v_tag, url);

                if ext == "exe" && arch_full.contains("sciter") {
                    if arch_full.contains("x64") || arch_full.contains("x86_64") || arch_full.contains("amd64") {
                        sciter_x64 = Some((url, "exe".into(), v_tag.to_string()));
                    } else {
                        sciter_x86 = Some((url, "exe".into(), v_tag.to_string()));
                    }
                } else if ext == "msi" {
                    msi = Some((url, "msi".into(), v_tag.to_string()));
                } else if ext == "exe" {
                    exe_plain = Some((url, "exe".into(), v_tag.to_string()));
                }
            }
        }

        if is_win7 {
            if is64 { sciter_x64.or(sciter_x86) } else { sciter_x86.or(sciter_x64) }
        } else {
            msi.or(sciter_x64.clone()).or(sciter_x86.clone()).or(exe_plain)
        }
    }

    // 1) Сначала пробуем /latest
    if let Some(found) = pick_from_html(&html_latest, "latest", is64, is_win7, archs, [&asset_re_dq, &asset_re_sq], log) {
        return Ok(found);
    }

    // 2) Ищем страницу тега (через <a> или JSON) и парсим ее.
    if let Some(mut tag_url) = resolve_latest_tag_url_from_html(&html_latest, log) {
    // Иногда теги бывают с 'v' и без - пробуем альтернативу, если запрос не удался.
    let html_tag = match http_get_string_via_certutil(&tag_url, log) {
        Ok(s) => s,
        Err(_) => {
            let alt = if tag_url.contains("/tag/v") {
                tag_url.replace("/tag/v", "/tag/")
            } else {
                tag_url.replace("/tag/", "/tag/v")
            };
            INFO!(log, "retry tag url: {}", alt);
            tag_url = alt.clone();
            http_get_string_via_certutil(&alt, log)?
        }
    };

    // Дамп страницы тега.
    let suffix = tag_url.rsplit('/').next().unwrap_or("tag");
    let _ = dump_html("tag", suffix, &html_tag, log_dir, log);

    // 1) пробуем прямо на странице тега
    if let Some(found) = pick_from_html(&html_tag, "tag", is64, is_win7, archs, [&asset_re_dq, &asset_re_sq], log) {
        return Ok(found);
    }

    // 2) если пусто - expanded_assets/<tag> (с 'v' и без)
    INFO!(log, "tag page has no asset anchors - trying expanded_assets ...");

    let ver = tag_url.rsplit('/').next().unwrap_or("").trim_start_matches('v').to_string();
    if ver.is_empty() {
        return Err("asset not found on tag page".to_string());
    }

    for prefix in &["v", ""] {
        let assets_url = format!("https://github.com/rustdesk/rustdesk/releases/expanded_assets/{}{}", prefix, ver);
        match http_get_string_via_certutil(&assets_url, log) {
            Ok(html_assets) => {
                let _ = dump_html("assets", &ver, &html_assets, log_dir, log);
                if let Some(found) = pick_from_html(&html_assets, "assets", is64, is_win7, archs, [&asset_re_dq, &asset_re_sq], log) {
                    return Ok(found);
                }
            }
            Err(e) => {
                INFO!(log, "expanded_assets fetch failed ({}{}): {}", prefix, ver, e);
            }
        }
    }

    return Err("asset not found on tag/expanded_assets page".to_string());
}


    // Если URL тега не найден.
    Err("не удалось найти подходящий ассет на странице releases/latest".to_string())
}





/* ---------------- Конфиги и пароль ---------------- */

fn build_toml() -> String {
    let mut s = String::new();
    s.push_str(&format!("rendezvous_server = \"{}\"\n", HBBS));
    s.push_str("nat_type = 2\n");
    s.push_str("serial = 0\n");
    s.push_str("unlock_pin = \"\"\n");
    s.push_str("trusted_devices = \"\"\n\n");

    s.push_str("[options]\n");
    s.push_str("av1-test = \"Y\"\n");
    let host = HBBS.split(':').next().unwrap_or(HBBS);
    s.push_str(&format!("custom-rendezvous-server = \"{}\"\n", host));
    s.push_str(&format!("key = \"{}\"\n", KEY));
    s.push_str("direct-access-port = \"21118\"\n");
    s.push_str("direct-server = \"Y\"\n");
    if let Some(r) = RELAY { s.push_str(&format!("relay_server = \"{}\"\n", r)); }
    s
}

fn localservice_cfg_dir() -> PathBuf {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
    PathBuf::from(windir).join(r"ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config")
}

fn user_cfg_dir() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(|appdata| PathBuf::from(appdata).join(r"RustDesk\config"))
}

fn programdata_cfg_dir() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\RustDesk\config")
}

fn write_configs(log: &mut fs::File) -> io::Result<()> {
    let toml = build_toml();

    // LocalService (служба).
    let svc_cfg_dir = localservice_cfg_dir();
    fs::create_dir_all(&svc_cfg_dir)?;
    let svc_cfg_path = svc_cfg_dir.join("RustDesk2.toml");
    fs::write(&svc_cfg_path, &toml)?;
    let _ = fs::write(svc_cfg_dir.join("RustDesk.toml"), &toml);
    let _ = run_logonly(log, "icacls", &format!(r#""{}" /grant *S-1-5-19:(OI)(CI)RX"#, svc_cfg_dir.display()));
    INFO!(log, "Конфиг (svc): {}", svc_cfg_path.display());

    // Профиль пользователя (GUI).
    if let Some(user_cfg_dir) = user_cfg_dir() {
        fs::create_dir_all(&user_cfg_dir)?;
        let user_cfg_path = user_cfg_dir.join("RustDesk2.toml");
        fs::write(&user_cfg_path, &toml)?;
        let _ = fs::write(user_cfg_dir.join("RustDesk.toml"), &toml);
        INFO!(log, "Конфиг (user): {}", user_cfg_path.display());
    }

    // ProgramData - на самых "чистых" системах иногда читают отсюда.
    let pd_dir = programdata_cfg_dir();
    let _ = fs::create_dir_all(&pd_dir);
    let _ = fs::write(pd_dir.join("RustDesk2.toml"), &toml);
    INFO!(log, "Конфиг (progdata): {}", pd_dir.join("RustDesk2.toml").display());

    Ok(())
}

fn parse_id_from_toml(path: &PathBuf, log: &mut fs::File) -> Option<String> {
    let data = fs::read_to_string(path).ok()?;
    let re = Regex::new(r#"(?m)^\s*id\s*=\s*"?([0-9A-Za-z\-]+)"?\s*$"#).ok()?;
    if let Some(c) = re.captures(&data) {
        let id = c.get(1)?.as_str().trim().to_string();
        if !id.is_empty() {
            INFO!(log, "ID найден в {}: {}", path.display(), id);
            return Some(id);
        }
    }
    None
}

fn get_rustdesk_id(rustexe: &PathBuf, log: &mut fs::File) -> Option<String> {
    if rustexe.exists() {
        if let Ok(o) = Command::new(rustexe).arg("--get-id").output() {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !s.is_empty() {
                    INFO!(log, "ID получен через --get-id: {}", s);
                    return Some(s);
                }
            }
        }
    }

    let mut dirs = Vec::new();
    dirs.push(localservice_cfg_dir());
    if let Some(user_dir) = user_cfg_dir() { dirs.push(user_dir); }
    dirs.push(programdata_cfg_dir());

    for dir in dirs {
        for name in &["RustDesk2.toml", "RustDesk.toml"] {
            let p = dir.join(name);
            if let Some(id) = parse_id_from_toml(&p, log) {
                return Some(id);
            }
        }
    }

    None
}

fn sync_user_config_to_service(log: &mut fs::File) -> bool {
    let Some(user_dir) = user_cfg_dir() else {
        log_file_warn(log, "Не найден APPDATA, пропускаю синхронизацию конфига пароля");
        return false;
    };

    let svc_dir = localservice_cfg_dir();
    let pd_dir = programdata_cfg_dir();
    let names = ["RustDesk2.toml", "RustDesk.toml"];
    let mut copied = false;

    for name in &names {
        let src = user_dir.join(name);
        if !src.exists() {
            continue;
        }
        for dst_dir in [&svc_dir, &pd_dir] {
            if let Err(e) = fs::create_dir_all(dst_dir) {
                log_file_warn(log, &format!("Не удалось создать {}: {}", dst_dir.display(), e));
                continue;
            }
            let dst = dst_dir.join(name);
            match fs::copy(&src, &dst) {
                Ok(_) => {
                    INFO!(log, "Синхронизирован {} -> {}", src.display(), dst.display());
                    copied = true;
                }
                Err(e) => {
                    log_file_warn(log, &format!("Ошибка копирования {} -> {}: {}", src.display(), dst.display(), e));
                }
            }
        }
    }

    if !copied {
        log_file_warn(log, "Файл пользовательского конфига не найден, пароль мог не примениться к службе");
    }
    copied
}

fn set_perm_password_safe(rustexe: &PathBuf, pw: &str, log: &mut fs::File) -> bool {
    let out = Command::new(rustexe)
        .args(&["--password", pw])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            log_file_info(log, "permanent password set");
            true
        }
        Ok(o) => {
            log_file_warn(log, &format!("--password exit {}", o.status.code().unwrap_or(-1)));
            if !o.stderr.is_empty() {
                log_file_warn(log, &format!("stderr: {}", String::from_utf8_lossy(&o.stderr).trim()));
            }
            false
        }
        Err(e) => { log_file_err(log, &format!("failed to set password: {}", e)); false }
    }
}


fn wait_for_rustdesk_service(timeout: Duration, log: &mut fs::File) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(name) = find_rustdesk_service_name() {
            log_file_info(log, &format!("Найдена служба: {}", name));
            return Some(name);
        }
        if Instant::now() > deadline {
            log_file_warn(log, "Ожидание регистрации службы истекло");
            return None;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}


#[derive(Debug, PartialEq, Eq)]
enum SvcState { Running, Stopped, StartPending, StopPending, NotFound }

fn find_rustdesk_service_name() -> Option<String> {
    for name in &["RustDesk Service","rustdesk","RustDesk"] {
        if Command::new("sc.exe").args(&["query", name]).output().map(|o| o.status.success()).unwrap_or(false) {
            return Some((*name).to_string());
        }
    }
    if let Ok(o) = Command::new("sc.exe").args(&["query","state=","all"]).output() {
        let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
        for block in text.split("\r\n\r\n") {
            if block.contains("rustdesk") {
                for line in block.lines() {
                    if let Some(rest) = line.strip_prefix("service_name:") {
                        return Some(rest.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

fn get_service_state(name: &str) -> SvcState {
    if let Ok(o) = Command::new("sc.exe").args(&["query", name]).output() {
        let s = String::from_utf8_lossy(&o.stdout).to_lowercase();
        if s.contains("running")       { return SvcState::Running; }
        if s.contains("stopped")       { return SvcState::Stopped; }
        if s.contains("start pending") { return SvcState::StartPending; }
        if s.contains("stop pending")  { return SvcState::StopPending; }
    }
    SvcState::NotFound
}

fn wait_for_state(name: &str, want: SvcState, timeout: Duration, log: &mut fs::File) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if get_service_state(name) == want {
            log_file_info(log, &format!("wait {:?} ok", want));
            return true;
        }
        std::thread::sleep(Duration::from_millis(350));
    }
    log_file_warn(log, &format!("wait {:?} timeout", want));
    false
}

fn ensure_service_present_and_auto(rustexe: &PathBuf, log: &mut fs::File) -> Option<String> {
    if let Some(name) = find_rustdesk_service_name() {
        let _ = run_logonly(log, "sc.exe", &format!("config {} start= auto", name));
        return Some(name);
    }
    let _ = run_args_timeout_logonly(log, &rustexe.display().to_string(), &["--install-service"], Duration::from_secs(20));
    if let Some(name) = find_rustdesk_service_name() {
        let _ = run_logonly(log, "sc.exe", &format!("config {} start= auto", name));
        return Some(name);
    }
    None
}

fn restart_service_safely(name: &str, log: &mut fs::File) {
    match get_service_state(name) {
        SvcState::Running => {
            let _ = run_logonly(log, "sc.exe", &format!("stop {}", name));
            let _ = wait_for_state(name, SvcState::Stopped, Duration::from_secs(10), log);
            let _ = run_logonly(log, "sc.exe", &format!("start {}", name));
            let _ = wait_for_state(name, SvcState::Running, Duration::from_secs(15), log);
        }
        _ => {
            let _ = run_logonly(log, "sc.exe", &format!("start {}", name));
            let _ = wait_for_state(name, SvcState::Running, Duration::from_secs(15), log);
        }
    }
}

fn stop_service_and_processes(log: &mut fs::File) {
    if let Some(svc) = find_rustdesk_service_name() {
        let _ = run_logonly(log, "sc.exe", &format!("stop {}", &svc));
        std::thread::sleep(Duration::from_millis(1200));
    }
    let _ = run_logonly(log, "taskkill.exe", "/IM rustdesk.exe /F /T");
    std::thread::sleep(Duration::from_millis(500));
}

/* ------------------- Установка MSI/EXE ------------------- */

fn install_msi(installer: &PathBuf, log: &mut fs::File) {
    let target_ver = extract_version_from_name(&installer.to_string_lossy()).unwrap_or_else(|| "0.0.0".to_string());
    let before = query_rustdesk_msi();

    let code = run_args_logonly(log, "msiexec.exe", &["/i", &installer.to_string_lossy(), "/qn", "/norestart", "ALLUSERS=1"]);
    log_file_info(log, &format!("msi /i -> {}", code));

    let after1 = query_rustdesk_msi();
    if let Some((v1, _)) = &after1 {
        if !ver_lt(v1, &target_ver) {
            log_file_info(log, &format!("msi upgraded to {}", v1));
            return;
        }
    }

    if let Some((ver_old, prodcode)) = before {
        log_file_info(log, &format!("msi remove old {} {}", ver_old, prodcode));
        let _ = run_args_logonly(log, "msiexec.exe", &["/x", &prodcode, "/qn", "/norestart"]);
    } else {
        log_file_info(log, "msi clean install (no previous)");
    }

    let code2 = run_args_logonly(log, "msiexec.exe", &["/i", &installer.to_string_lossy(), "/qn", "/norestart", "ALLUSERS=1"]);
    log_file_info(log, &format!("msi clean install -> {}", code2));
}

fn install_exe_with_timeout(installer: &PathBuf, log: &mut fs::File) {
    let mut child = Command::new(installer)
        .arg("--silent-install")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let deadline = Instant::now() + Duration::from_secs(300);
    let mut seen_binary = false;

    loop {
        // Фиксируем первый момент появления бинарника, процесс не трогаем.
        if !seen_binary {
            if let Some(p) = find_rustdesk_exe() {
                log_file_info(log, &format!("exe detected binary at {}", p.display()));
                seen_binary = true;
            }
        }

        // Нормальное завершение установщика.
        if let Ok(Some(st)) = child.try_wait() {
            log_file_info(log, &format!("exe exit {}", st.code().unwrap_or(-1)));
            break;
        }

        // При тайм-ауте завершаем установщик.
        if Instant::now() > deadline {
            log_file_warn(log, "exe timeout -> killing installer");
            let _ = child.kill();
            break;
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

/* ------------- MSI: версия/продукт-код (реестр) ------------- */

fn run_capture(file: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(file).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}
fn parse_reg_value(blob: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?im)^\s*{}\s+REG_\w+\s+(.+?)\s*$", regex::escape(name))).ok()?;
    re.captures(blob).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string())
}
fn query_rustdesk_msi() -> Option<(String,String)> {
    let keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];
    let guid_re = Regex::new(r"\{[0-9A-Fa-f\-]{36}\}").ok()?;
    for key in keys {
        let list = run_capture("reg.exe", &["query", key])?;
        for line in list.lines() {
            let sub = line.trim();
            if !sub.starts_with("HKEY") { continue; }
            let dn = run_capture("reg.exe", &["query", sub, "/v", "DisplayName"])?;
            if !dn.to_lowercase().contains("rustdesk") { continue; }
            let dv = run_capture("reg.exe", &["query", sub, "/v", "DisplayVersion"])?;
            let us = run_capture("reg.exe", &["query", sub, "/v", "UninstallString"])?;
            let ver = parse_reg_value(&dv, "DisplayVersion")?;
            let usval = parse_reg_value(&us, "UninstallString").unwrap_or_default();
            if let Some(m) = guid_re.captures(&usval) { return Some((ver, m.get(0).unwrap().as_str().to_string())); }
        }
    }
    None
}
fn ver_lt(a: &str, b: &str) -> bool {
    let mut pa = a.trim_start_matches('v').split('.').map(|x| x.parse::<i64>().unwrap_or(0));
    let mut pb = b.trim_start_matches('v').split('.').map(|x| x.parse::<i64>().unwrap_or(0));
    for _ in 0..3 {
        let (aa, bb) = (pa.next().unwrap_or(0), pb.next().unwrap_or(0));
        if aa < bb { return true; }
        if aa > bb { return false; }
    }
    false
}
// Извлечь номер версии из имени файла/пути: rustdesk-1.4.2-x86_64.msi -> "1.4.2".
fn extract_version_from_name(name: &str) -> Option<String> {
    // Берем первые три компонента X.Y.Z.
    let re = regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
    re.captures(name)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}


/* ------------------------- Утилиты ------------------------- */

fn shlex_split(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut q) = (Vec::new(), String::new(), false);
    for c in s.chars() {
        match c {
            '"' => { q = !q; }
            ' ' if !q => { if !cur.is_empty() { out.push(cur.clone()); cur.clear(); } }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}
fn run_logonly(log: &mut fs::File, file: &str, args: &str) -> i32 {
    let out = Command::new(file).args(shlex_split(args)).stdout(Stdio::piped()).stderr(Stdio::piped()).output();
    match out {
        Ok(o) => {
            if !o.stdout.is_empty() { log_file_line(log, "STDOUT", String::from_utf8_lossy(&o.stdout).trim()); }
            if !o.stderr.is_empty() { log_file_line(log, "STDERR", String::from_utf8_lossy(&o.stderr).trim()); }
            o.status.code().unwrap_or(-1)
        }
        Err(e) => { log_file_err(log, &format!("{} {}: {}", file, args, e)); -1 }
    }
}
fn run_args_logonly(log: &mut fs::File, file: &str, args: &[&str]) -> i32 {
    let out = Command::new(file).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output();
    match out {
        Ok(o) => {
            if !o.stdout.is_empty() { log_file_line(log, "STDOUT", String::from_utf8_lossy(&o.stdout).trim()); }
            if !o.stderr.is_empty() { log_file_line(log, "STDERR", String::from_utf8_lossy(&o.stderr).trim()); }
            o.status.code().unwrap_or(-1)
        }
        Err(e) => { log_file_err(log, &format!("{} {:?}: {}", file, args, e)); -1 }
    }
}
fn run_args_timeout_logonly(log: &mut fs::File, file: &str, args: &[&str], timeout: Duration) -> i32 {
    let mut child = Command::new(file).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn");
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            let code = status.code().unwrap_or(-1);
            log_file_line(log, "PROC", &format!("{} {:?} -> {}", file, args, code));
            return code;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            log_file_warn(log, &format!("timeout {} {:?}", file, args));
            return -100;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}


// Ожидание появления rustdesk.exe.
fn wait_for_rustdesk_exe(max_wait: Duration, log: &mut fs::File) -> Option<PathBuf> {
    let deadline = Instant::now() + max_wait;
    loop {
        if let Some(p) = find_rustdesk_exe() {
            return Some(p);
        }
        if Instant::now() > deadline {
            log_file_warn(log, "wait rustdesk.exe timeout");
            return None;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// Поиск rustdesk.exe.
fn find_rustdesk_exe() -> Option<PathBuf> {
    let pf  = std::env::var("ProgramFiles").ok();
    let pf2 = std::env::var("ProgramFiles(x86)").ok();
    let mut cands = vec![];
    if let Some(p) = pf  { cands.push(PathBuf::from(p).join(r"RustDesk\rustdesk.exe")); }
    if let Some(p) = pf2 { cands.push(PathBuf::from(p).join(r"RustDesk\rustdesk.exe")); }
    cands.into_iter().find(|p| p.exists())
}

/* --------------------- Elevation (UAC) --------------------- */

fn is_elevated() -> bool {
    const TOKEN_QUERY: u32 = 0x0008;
    unsafe {
        let mut token: HANDLE = null();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 { return false; }
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed(); let mut len: u32 = 0;
        if GetTokenInformation(token, TokenElevation, &mut elev as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len) != 0 {
            if elev.TokenIsElevated != 0 { return true; }
        }
        is_member_admin(token)
    }
}
fn is_member_admin(token: HANDLE) -> bool {
    use windows_sys::Win32::Foundation::BOOL;
    unsafe {
        let mut sid: [u8; SECURITY_MAX_SID_SIZE as usize] = [0; SECURITY_MAX_SID_SIZE as usize];
        let mut size = sid.len() as u32;
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, std::ptr::null_mut(), sid.as_mut_ptr() as *mut c_void, &mut size) == 0 { return false; }
        let mut is_member: BOOL = 0;
        if CheckTokenMembership(token, sid.as_ptr() as *mut c_void, &mut is_member) == 0 { return false; }
        is_member != 0
    }
}
fn relaunch_as_admin() {
    let exe = std::env::current_exe().unwrap();
    let args_vec: Vec<String> = std::env::args().skip(1).collect();
    let ps_cmd = if args_vec.is_empty() {
        format!("Start-Process -Verb RunAs -FilePath '{}'", exe.display())
    } else {
        let joined = args_vec.join(" ").replace('\'', "''");
        format!("Start-Process -Verb RunAs -FilePath '{}' -ArgumentList '{}'", exe.display(), joined)
    };
    let _ = Command::new("powershell").args(["-NoProfile","-ExecutionPolicy","Bypass","-Command",&ps_cmd]).spawn();
}

/* ------------------------- Fatal ------------------------- */

fn fatal(log: &std::path::Path, logfile: &mut fs::File, msg: &str) -> ! {
    ERR!(logfile, "{}", msg);
    println!("Лог: {}", log.display());
    println!("Нажмите Enter, чтобы закрыть окно...");
    let _ = std::io::stdin().read_line(&mut String::new());
    std::process::exit(1)
}















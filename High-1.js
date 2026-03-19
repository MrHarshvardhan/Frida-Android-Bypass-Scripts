/**
 * Frida Android Bypass — Banking Grade
 * Supports : Android 7–14 | Java · Flutter · React Native · NDK
 * Bypasses  : SSL pinning · Root detection · Anti-debug · Integrity checks
 *
 * Design rules:
 *   1. Native hooks fire immediately — before Java.perform, before app init.
 *   2. Java.perform runs once. One enumerate. Zero repeated class scans.
 *   3. Every hook is wrapped in try/catch. A missing class never kills the script.
 *   4. No box-drawing. No INTEL objects. No strategy theater. Logs are one-liners.
 *   5. Execution order is strict:
 *        native anti-detect → native root/env → native SSL
 *        → Java anti-detect → Java root/env → Java SSL → exit traps
 *
 * Execution order matters because:
 *   - Banking apps run root checks in Application.onCreate() — before any UI.
 *   - Frida thread names exist from the moment the agent loads — before Java.perform.
 *   - SSL pinning fires on the first network call — after login screen appears.
 *   - Exit/crash traps are last because they must not interfere with the above hooks.
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — NATIVE ANTI-DETECTION
// Must be first. Frida thread names and /proc/maps entries exist the moment
// the agent is injected — before Java.perform() is even called.
// ─────────────────────────────────────────────────────────────────────────────

// 1a. Hide Frida agent from /proc/self/maps via fopen redirect.
//     Apps read /proc/self/maps to scan for "frida", "gadget", "linjector".
//     We also redirect /proc/self/status to block TracerPid reads.
//     Single unified fopen hook — no duplicate attach.
(function hookFopen() {
    const BLOCKED_PATHS = [
        // Root binaries and Magisk
        "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
        "/sbin/su", "/system/bin/su", "/system/bin/failsafe/su",
        "/system/xbin/su", "/system/xbin/busybox", "/system/xbin/daemonsu",
        "/system/sbin/su", "/system/sd/xbin/su", "/vendor/bin/su",
        "/su/bin/su", "/cache/su", "/data/su", "/dev/su",
        "/system/bin/.ext/su", "/system/usr/we-need-root/su",
        "/system/app/Superuser.apk", "/system/app/Kinguser.apk",
        "/system/etc/init.d/99SuperSUDaemon",
        // Magisk v24+ / Zygisk
        "/data/adb/magisk", "/data/adb/magisk/magisk", "/data/adb/magisk/magisk64",
        "/data/adb/magisk/magiskpolicy", "/data/adb/magisk.db", "/data/adb/magisk.img",
        "/data/adb/magisk_simple", "/data/adb/modules", "/data/adb/modules_update",
        "/sbin/.magisk", "/cache/.disable_magisk", "/dev/.magisk.unblock",
        "/cache/magisk.log", "/init.magisk.rc",
        "/data/adb/magisk/zygisk", "/system/lib/zygisk.so", "/system/lib64/zygisk.so",
        // KernelSU
        "/data/adb/ksu", "/data/adb/ksud", "/data/adb/modules/.ksu",
        // APatch
        "/data/adb/ap", "/data/adb/apd",
        // Legacy
        "/system/xbin/ku.sud", "/system/xbin/magisk",
        "/dev/com.koushikdutta.superuser.daemon/",
    ];

    const BLOCKED_KEYWORDS = ["magisk", "/ksu", "/adb/ap", "frida", "gadget", "linjector"];

    const fopen = Module.findExportByName("libc.so", "fopen");
    if (!fopen) return;

    Interceptor.attach(fopen, {
        onEnter(args) {
            try {
                const path = args[0].readUtf8String();
                this.blocked = false;

                // /proc/self/status — block to hide TracerPid
                if (path === "/proc/self/status") {
                    args[0].writeUtf8String("/notexists");
                    this.blocked = true;
                    return;
                }

                const block =
                    BLOCKED_PATHS.indexOf(path) >= 0 ||
                    BLOCKED_KEYWORDS.some(k => path.indexOf(k) >= 0);

                if (block) {
                    args[0].writeUtf8String("/notexists");
                    this.blocked = true;
                }
            } catch(_) {}
        }
    });
})();

// 1b. access() and stat family — same block list as fopen.
//     These are used when apps call File.exists() via native path or
//     directly call access(path, F_OK) to check for su/magisk.
(function hookAccess() {
    const BLOCKED_PATHS = [
        "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
        "/sbin/su", "/system/bin/su", "/system/xbin/su", "/system/xbin/busybox",
        "/system/xbin/daemonsu", "/system/sbin/su", "/vendor/bin/su",
        "/su/bin/su", "/system/app/Superuser.apk", "/system/app/Kinguser.apk",
        "/data/adb/magisk", "/data/adb/magisk/magisk", "/data/adb/modules",
        "/sbin/.magisk", "/data/adb/ksu", "/data/adb/ksud",
        "/data/adb/ap", "/data/adb/apd",
    ];
    const BLOCKED_KW = ["magisk", "/ksu", "/adb/ap", "frida", "gadget"];

    const shouldBlock = (path) =>
        BLOCKED_PATHS.indexOf(path) >= 0 || BLOCKED_KW.some(k => path.indexOf(k) >= 0);

    // access()
    const accessFn = Module.findExportByName("libc.so", "access");
    if (accessFn) {
        Interceptor.attach(accessFn, {
            onEnter(args) {
                try { this.path = args[0].readUtf8String(); } catch(_) { this.path = ""; }
            },
            onLeave(retval) {
                if (retval.toInt32() === 0 && shouldBlock(this.path)) {
                    retval.replace(ptr(-1));
                }
            }
        });
    }

    // stat / __xstat / stat64 / __xstat64
    ["stat", "__xstat", "stat64", "__xstat64"].forEach(fn => {
        const addr = Module.findExportByName("libc.so", fn);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    // __xstat has version as args[0], path at args[1]
                    const idx = fn.startsWith("__x") ? 1 : 0;
                    this.path = args[idx].readUtf8String();
                } catch(_) { this.path = ""; }
            },
            onLeave(retval) {
                if (retval.toInt32() === 0 && shouldBlock(this.path)) {
                    retval.replace(ptr(-1));
                }
            }
        });
    });
})();

// 1c. execve — native exec root checks.
//     Java Runtime.exec hooks below cover the Java layer.
//     execve catches NDK-level exec calls that bypass Java entirely.
(function hookExecve() {
    const addr = Module.findExportByName("libc.so", "execve");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                const cmd = args[0].readUtf8String();
                if (!cmd) return;
                if (cmd.indexOf("su") !== -1 || cmd.indexOf("magisk") !== -1 ||
                    cmd.indexOf("getprop") !== -1 || cmd === "/system/bin/sh" ||
                    cmd === "mount" || cmd === "id") {
                    args[0].writeUtf8String("/system/bin/grep");
                }
            } catch(_) {}
        }
    });
})();

// 1d. system() — another native exec path.
(function hookSystem() {
    const addr = Module.findExportByName("libc.so", "system");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                const cmd = args[0].readUtf8String();
                if (!cmd) return;
                const block = cmd === "su" || cmd === "mount" || cmd === "id" ||
                    cmd.indexOf("getprop") !== -1 || cmd.indexOf("build.prop") !== -1 ||
                    cmd.indexOf("magisk") !== -1;
                if (block) args[0].writeUtf8String("grep");
            } catch(_) {}
        }
    });
})();

// 1e. ptrace — blocks PTRACE_TRACEME (self anti-debug lock) and PTRACE_ATTACH.
//     Banking apps call ptrace(PTRACE_TRACEME) to occupy the debugger slot
//     so no external debugger can attach. We let it appear to succeed (return 0)
//     without actually executing — so we can still attach later if needed.
(function hookPtrace() {
    const addr = Module.findExportByName("libc.so", "ptrace");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            const req = args[0].toInt32();
            // PTRACE_TRACEME=0, PTRACE_ATTACH=16
            this.fake = (req === 0 || req === 16);
        },
        onLeave(retval) {
            if (this.fake) retval.replace(ptr(0));
        }
    });
})();

// 1f. __system_property_get — native property spoof.
//     Covers what Java SystemProperties.get misses when apps call it via JNI.
(function hookSysPropGet() {
    const FAKE = {
        "ro.build.tags":        "release-keys",
        "ro.build.type":        "user",
        "ro.debuggable":        "0",
        "ro.secure":            "1",
        "service.adb.root":     "0",
        "ro.build.selinux":     "1",
        "ro.build.fingerprint": "google/redfin/redfin:11/RQ3A.210805.001/7474174:user/release-keys",
    };

    const addr = Module.findExportByName("libc.so", "__system_property_get");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            try { this.key = args[0].readCString(); } catch(_) { this.key = ""; }
            this.ret = args[1];
        },
        onLeave(_) {
            if (this.key && FAKE[this.key]) {
                const val = FAKE[this.key];
                const p = Memory.allocUtf8String(val);
                Memory.copy(this.ret, p, val.length + 1);
            }
        }
    });
})();

// 1g. kill() and raise() — trap self-kill used when tampering is detected.
//     SIGKILL(9) and SIGABRT(6) on own PID are the common patterns.
//     SIGSEGV(11) intentional crash is used by some banking SDKs.
(function hookKillSignals() {
    const myPid = Process.id;

    const killAddr = Module.findExportByName("libc.so", "kill");
    if (killAddr) {
        Interceptor.attach(killAddr, {
            onEnter(args) {
                const pid = args[0].toInt32();
                const sig = args[1].toInt32();
                if (pid === myPid && (sig === 9 || sig === 6 || sig === 11)) {
                    console.log("[trap] kill(" + sig + ") on self blocked");
                    args[1] = ptr(0); // signal 0 = no-op
                }
            }
        });
    }

    const raiseAddr = Module.findExportByName("libc.so", "raise");
    if (raiseAddr) {
        Interceptor.attach(raiseAddr, {
            onEnter(args) {
                const sig = args[0].toInt32();
                if (sig === 6 || sig === 9 || sig === 11) {
                    console.log("[trap] raise(" + sig + ") blocked");
                    args[0] = ptr(0);
                }
            }
        });
    }
})();

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 — NATIVE SSL BYPASS
// Runs before Java.perform. Native SSL hooks must be in place before the
// first TLS handshake, which can happen as early as splash screen.
// ─────────────────────────────────────────────────────────────────────────────

// 2a. libssl.so — SSL_CTX_set_verify
//     Apps using NDK-level TLS set a custom verify callback here.
//     We null out both the mode (→ SSL_VERIFY_NONE) and the callback.
(function hookNativeSSL() {
    const libssl = Process.findModuleByName("libssl.so");
    if (!libssl) return;

    const setVerify = libssl.findExportByName("SSL_CTX_set_verify");
    if (setVerify) {
        Interceptor.attach(setVerify, {
            onEnter(args) {
                args[1] = ptr(0); // SSL_VERIFY_NONE
                args[2] = ptr(0); // null callback
            }
        });
        console.log("[+] SSL_CTX_set_verify");
    }

    const libcrypto = Process.findModuleByName("libcrypto.so");
    if (!libcrypto) return;

    const x509verify = libcrypto.findExportByName("X509_verify_cert");
    if (x509verify) {
        Interceptor.attach(x509verify, {
            onLeave(retval) {
                if (retval.toInt32() !== 1) retval.replace(ptr(1));
            }
        });
        console.log("[+] X509_verify_cert");
    }
})();

// 2b. Flutter / BoringSSL — libflutter.so
//     Flutter embeds BoringSSL and never touches javax.net.ssl.
//     We pattern-scan for ssl_verify_peer_cert (arm64 prologue, Flutter 3.x stable).
//     If the export is present by name (debug builds), we use that directly.
//     Pattern: if Flutter version changes, update the byte sequence.
(function hookFlutterSSL() {
    const flutter = Process.findModuleByName("libflutter.so");
    if (!flutter) return;

    // Try named export first (Flutter debug / profile builds)
    const namedExport = flutter.findExportByName("ssl_crypto_x509_session_verify_cert_chain");
    if (namedExport) {
        Interceptor.attach(namedExport, {
            onLeave(retval) { retval.replace(ptr(1)); }
        });
        console.log("[+] Flutter ssl_crypto_x509_session_verify_cert_chain (named export)");
    }

    // Pattern scan for ssl_verify_peer_cert — arm64 Flutter 3.x release builds.
    // Returns ssl_verify_result_t: 0 = ok, 1 = error. We force 0.
    const ARM64_PATTERN = "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9";
    Memory.scan(flutter.base, flutter.size, ARM64_PATTERN, {
        onMatch(addr) {
            Interceptor.attach(addr, {
                onLeave(retval) { retval.replace(ptr(0)); }
            });
            console.log("[+] Flutter ssl_verify_peer_cert (pattern @" + addr + ")");
        },
        onError() {},
        onComplete() {}
    });
})();

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 — JAVA LAYER
// Single Java.perform call. One class enumeration. All Java hooks inside.
// ─────────────────────────────────────────────────────────────────────────────

Java.perform(function() {

    // ── Detect obfuscation early — one enumeration, reused below ──────────────
    // We enumerate once here. If class count with 1-2 char names > threshold,
    // we enable the obfuscated OkHttp scan. No repeated enumerations.
    const loadedClasses = Java.enumerateLoadedClassesSync();
    let shortNameCount = 0;
    for (let i = 0; i < loadedClasses.length; i++) {
        const parts = loadedClasses[i].split(".");
        const simple = parts[parts.length - 1];
        if (simple.length <= 2 && /^[a-z]+$/.test(simple)) shortNameCount++;
    }
    const isObfuscated = shortNameCount > 300;
    const isFlutter    = !!Process.findModuleByName("libflutter.so");
    const isRN         = loadedClasses.some(c => c.indexOf("com.facebook.react") >= 0);

    console.log("[i] obfuscated=" + isObfuscated + " flutter=" + isFlutter + " rn=" + isRN);

    // ── 3a. Frida thread name hiding ─────────────────────────────────────────
    // Must be first Java hook. Frida threads exist before Java.perform.
    // Apps enumerate Thread.getAllStackTraces() or scan thread names for
    // "gmain", "gdbus", "gum-js-loop", "pool-frida".
    try {
        const Thread = Java.use("java.lang.Thread");
        Thread.getName.implementation = function() {
            const name = this.getName.call(this);
            const lc = name.toLowerCase();
            if (lc === "gmain" || lc === "gdbus" || lc.indexOf("gum-js") >= 0 ||
                lc.indexOf("frida") >= 0 || lc.indexOf("linjector") >= 0 ||
                lc.indexOf("pool-frida") >= 0) {
                return "pool-" + (Math.random() * 9999 | 0);
            }
            return name;
        };
        console.log("[+] Thread.getName (Frida thread hiding)");
    } catch(e) { console.log("[ ] Thread.getName"); }

    // ── 3b. /proc/maps and build.prop read — BufferedReader filter ────────────
    // Single hook. Covers:
    //   - /proc/self/maps scan for frida/gadget/zygisk/magisk
    //   - build.prop read for ro.build.tags=test-keys
    //   - /proc/self/status TracerPid (if app reads via Java)
    // Do NOT hook overload('boolean') AND overload() separately — second wins.
    // Use overload() which covers the common path.
    try {
        const BR = Java.use("java.io.BufferedReader");
        BR.readLine.overload().implementation = function() {
            let line = this.readLine.overload().call(this);
            if (line === null) return null;
            const lc = line.toLowerCase();
            // Strip lines exposing Frida or root tools in maps
            if (lc.indexOf("frida") >= 0 || lc.indexOf("gadget") >= 0 ||
                lc.indexOf("linjector") >= 0 || lc.indexOf("gum-js") >= 0 ||
                lc.indexOf("zygisk") >= 0 || lc.indexOf("lsplant") >= 0) {
                return "";
            }
            // Spoof TracerPid in /proc/self/status
            if (line.indexOf("TracerPid:") >= 0) return "TracerPid:\t0";
            // Spoof test-keys in build.prop
            if (line.indexOf("ro.build.tags=test-keys") >= 0) {
                return line.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
            return line;
        };
        console.log("[+] BufferedReader.readLine (maps/TracerPid/build.prop)");
    } catch(e) { console.log("[ ] BufferedReader.readLine"); }

    // ── 3c. isDebuggerConnected ───────────────────────────────────────────────
    // Simple boolean kill. Banking apps call this in a background thread loop.
    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() { return false; };
        console.log("[+] Debug.isDebuggerConnected");
    } catch(e) { console.log("[ ] isDebuggerConnected"); }

    // ── 3d. Root file checks — Java layer ────────────────────────────────────
    // Covers apps that use java.io.File.exists() to check for su/magisk.
    // Also covers UnixFileSystem.checkAccess which File.exists() calls internally.
    const ROOT_BINS = [
        "su", "busybox", "supersu", "magisk", "magisk64", "magiskpolicy",
        "ksud", "ksu", "apd", "Superuser.apk", "KingoUser.apk", "SuperSu.apk",
    ];
    const ROOT_PATHS_JAVA = [
        "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
        "/sbin/su", "/system/bin/su", "/system/xbin/su", "/system/xbin/busybox",
        "/system/xbin/daemonsu", "/system/sbin/su", "/vendor/bin/su",
        "/su/bin/su", "/system/app/Superuser.apk", "/system/app/Kinguser.apk",
        "/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu",
        "/data/adb/ksud", "/data/adb/ap", "/data/adb/apd", "/sbin/.magisk",
    ];

    try {
        const File = Java.use("java.io.File");
        File.exists.implementation = function() {
            const name = this.getName.call(this);
            const path = this.getAbsolutePath.call(this);
            if (ROOT_BINS.indexOf(name) >= 0 || ROOT_PATHS_JAVA.indexOf(path) >= 0 ||
                path.indexOf("magisk") >= 0 || path.indexOf("/ksu") >= 0 ||
                path.indexOf("/adb/ap") >= 0) {
                return false;
            }
            return this.exists.call(this);
        };
        console.log("[+] File.exists (root path block)");
    } catch(e) { console.log("[ ] File.exists"); }

    try {
        const UFS = Java.use("java.io.UnixFileSystem");
        UFS.checkAccess.implementation = function(file, access) {
            const path = file.getAbsolutePath();
            if (ROOT_PATHS_JAVA.indexOf(path) >= 0 ||
                path.indexOf("magisk") >= 0 || path.indexOf("/ksu") >= 0 ||
                path.indexOf("/adb/ap") >= 0) {
                return false;
            }
            return this.checkAccess(file, access);
        };
        console.log("[+] UnixFileSystem.checkAccess");
    } catch(e) { console.log("[ ] UnixFileSystem.checkAccess"); }

    // ── 3e. Root package checks — Android 12 and 13+ aware ───────────────────
    // getPackageInfo has 2 signatures. Android 13+ uses PackageInfoFlags object.
    // Missing the Flags overload means the hook silently never fires on API 33+.
    const ROOT_PKGS = [
        "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "eu.chainfire.supersu", "eu.chainfire.supersu.pro",
        "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "com.yellowes.su", "com.topjohnwu.magisk",
        "me.weishu.kernelsu",        // KernelSU
        "com.bmax.raptor.superuser", // APatch
        "io.github.huskydg.magisk",  // Magisk fork
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
        "de.robv.android.xposed.installer", "com.saurik.substrate",
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "me.phh.superuser", "com.kingouser.com",
    ];

    try {
        const APM = Java.use("android.app.ApplicationPackageManager");

        // Legacy int-flags overload (API < 33)
        try {
            APM.getPackageInfo.overload("java.lang.String", "int")
                .implementation = function(pkg, flags) {
                    if (ROOT_PKGS.indexOf(pkg) >= 0) pkg = "not.installed.fake";
                    return this.getPackageInfo(pkg, flags);
                };
        } catch(_) {}

        // API 33+ PackageInfoFlags object overload
        try {
            APM.getPackageInfo.overload(
                "java.lang.String", "android.content.pm.PackageManager$PackageInfoFlags"
            ).implementation = function(pkg, flags) {
                if (ROOT_PKGS.indexOf(pkg) >= 0) pkg = "not.installed.fake";
                return this.getPackageInfo(pkg, flags);
            };
        } catch(_) {}

        // getInstalledPackages — some apps iterate full list
        try {
            APM.getInstalledPackages.overload("int").implementation = function(flags) {
                const list = this.getInstalledPackages(flags);
                const it = list.iterator();
                while (it.hasNext()) {
                    const info = it.next();
                    if (ROOT_PKGS.indexOf(info.packageName.value) >= 0) it.remove();
                }
                return list;
            };
        } catch(_) {}

        console.log("[+] PackageManager (all overloads incl API33)");
    } catch(e) { console.log("[ ] PackageManager"); }

    // ── 3f. System properties — Java layer ───────────────────────────────────
    const PROP_FAKE = {
        "ro.build.tags": "release-keys", "ro.build.type": "user",
        "ro.debuggable": "0", "ro.secure": "1", "service.adb.root": "0",
        "ro.build.selinux": "1",
    };
    const PROP_KEYS = Object.keys(PROP_FAKE);

    try {
        const SP = Java.use("android.os.SystemProperties");
        SP.get.overload("java.lang.String").implementation = function(name) {
            if (PROP_KEYS.indexOf(name) >= 0) return PROP_FAKE[name];
            return this.get.call(this, name);
        };
        SP.get.overload("java.lang.String", "java.lang.String").implementation = function(name, def) {
            if (PROP_KEYS.indexOf(name) >= 0) return PROP_FAKE[name];
            return this.get.call(this, name, def);
        };
        console.log("[+] SystemProperties.get");
    } catch(e) { console.log("[ ] SystemProperties.get"); }

    // String.contains("test-keys") — used in ro.build.tags checks
    try {
        const Str = Java.use("java.lang.String");
        Str.contains.implementation = function(s) {
            if (s === "test-keys") return false;
            return this.contains.call(this, s);
        };
        console.log("[+] String.contains (test-keys)");
    } catch(e) { console.log("[ ] String.contains"); }

    // ── 3g. Build field spoof — emulator and fingerprint detection ────────────
    // Apps check Build.FINGERPRINT for "generic", "unknown", "sdk", "emulator".
    // Also check Build.TAGS for "test-keys".
    try {
        const Build = Java.use("android.os.Build");
        const SPOOF = {
            TAGS: "release-keys", TYPE: "user",
            FINGERPRINT: "google/redfin/redfin:11/RQ3A.210805.001/7474174:user/release-keys",
            MANUFACTURER: "Google", MODEL: "Pixel 5",
            BRAND: "google", DEVICE: "redfin", PRODUCT: "redfin", HARDWARE: "redfin",
        };
        for (const [field, value] of Object.entries(SPOOF)) {
            try {
                const f = Build.class.getDeclaredField(field);
                f.setAccessible(true);
                f.set(null, value);
            } catch(_) {}
        }
        console.log("[+] Build field spoof (fingerprint + emulator fields)");
    } catch(e) { console.log("[ ] Build field spoof"); }

    // ── 3h. Runtime.exec — Java shell command root checks ────────────────────
    // Called by apps doing: Runtime.getRuntime().exec("su")
    // Covers all 6 overloads. Funnels suspects to a fake command.
    try {
        const RT = Java.use("java.lang.Runtime");
        const SUSPECT = ["su", "mount", "id", "sh", "getprop", "build.prop", "magisk", "ksud"];
        const isSuspect = cmd => SUSPECT.some(s => cmd.indexOf(s) !== -1);
        const FAKE_CMD  = cmd => (cmd === "su" || cmd.indexOf("magisk") !== -1)
            ? "thiscmdwillnotexist" : "grep";

        const exec1 = RT.exec.overload("java.lang.String");
        [
            exec1,
            RT.exec.overload("java.lang.String", "[Ljava.lang.String;"),
            RT.exec.overload("java.lang.String", "[Ljava.lang.String;", "java.io.File"),
        ].forEach(ov => {
            try {
                ov.implementation = function() {
                    const cmd = arguments[0];
                    const c = typeof cmd === "string" ? cmd : String(cmd);
                    if (isSuspect(c)) return exec1.call(this, FAKE_CMD(c));
                    return ov.apply(this, arguments);
                };
            } catch(_) {}
        });

        // Array overloads
        [
            RT.exec.overload("[Ljava.lang.String;"),
            RT.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;"),
            RT.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File"),
        ].forEach(ov => {
            try {
                ov.implementation = function() {
                    const arr = arguments[0];
                    if (arr && arr.length > 0) {
                        const c = String(arr[0]);
                        if (isSuspect(c)) return exec1.call(this, FAKE_CMD(c));
                    }
                    return ov.apply(this, arguments);
                };
            } catch(_) {}
        });

        console.log("[+] Runtime.exec (all 6 overloads)");
    } catch(e) { console.log("[ ] Runtime.exec"); }

    // ProcessBuilder
    try {
        const PB = Java.use("java.lang.ProcessBuilder");
        const SUSPECT_PB = ["su", "mount", "id", "getprop", "build.prop", "magisk"];
        PB.start.implementation = function() {
            const cmd = this.command.call(this);
            for (let i = 0; i < cmd.size(); i++) {
                const c = String(cmd.get(i));
                if (SUSPECT_PB.some(s => c.indexOf(s) !== -1)) {
                    this.command.call(this, ["grep"]);
                    return this.start.call(this);
                }
            }
            return this.start.call(this);
        };
        console.log("[+] ProcessBuilder.start");
    } catch(e) { console.log("[ ] ProcessBuilder.start"); }

    // ProcessImpl — guarded. Not present on all Android versions.
    // Checking before using avoids silent failures.
    if (loadedClasses.indexOf("java.lang.ProcessImpl") !== -1) {
        try {
            const Str = Java.use("java.lang.String");
            const PI = Java.use("java.lang.ProcessImpl");
            PI.start.implementation = function(cmdarr, env, dir, redirects, errStream) {
                const c0 = cmdarr[0] || "";
                const c1 = cmdarr.length > 1 ? cmdarr[1] : "";
                const isRoot = c0 === "su" || c0 === "mount" || c0 === "id" ||
                    c0.indexOf("magisk") !== -1 ||
                    (c0 === "getprop" && ["ro.secure","ro.debuggable","ro.build.tags"].indexOf(c1) >= 0) ||
                    (c0.indexOf("which") >= 0 && c1 === "su");
                if (isRoot) {
                    arguments[0] = Java.array("java.lang.String", [Str.$new("thiscmdwillnotexist")]);
                    return PI.start.apply(this, arguments);
                }
                return PI.start.apply(this, arguments);
            };
            console.log("[+] ProcessImpl.start");
        } catch(e) { console.log("[ ] ProcessImpl.start"); }
    }

    // ── 3i. SSL Pinning — Java layer ─────────────────────────────────────────
    // Ordered from most common (OkHttp3) to least (IBM WorkLight).
    // Each hook is independent — one failure does not block others.

    // SSLPeerUnverifiedException auto-patcher.
    // When an unexpected pinning method throws this, we locate the throwing class
    // dynamically and patch it. Handles obfuscated and unknown pinners.
    try {
        const SSLErr = Java.use("javax.net.ssl.SSLPeerUnverifiedException");
        SSLErr.$init.implementation = function(str) {
            try {
                const stack = Java.use("java.lang.Thread").currentThread().getStackTrace();
                const idx = stack.findIndex(f =>
                    f.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException");
                if (idx >= 0 && idx + 1 < stack.length) {
                    const caller = stack[idx + 1];
                    const cls    = caller.getClassName();
                    const method = caller.getMethodName();
                    const Cls    = Java.use(cls);
                    const M      = Cls[method];
                    if (M && !M.implementation) {
                        const retType = M.returnType.type;
                        M.implementation = function() {
                            console.log("[auto-patch] " + cls + "." + method);
                            return retType === "void" ? undefined : null;
                        };
                    }
                }
            } catch(_) {}
            return this.$init(str);
        };
        console.log("[+] SSLPeerUnverifiedException auto-patcher");
    } catch(e) { console.log("[ ] SSLPeerUnverifiedException auto-patcher"); }

    // HttpsURLConnection
    ["setDefaultHostnameVerifier", "setSSLSocketFactory", "setHostnameVerifier"].forEach(m => {
        try {
            Java.use("javax.net.ssl.HttpsURLConnection")[m].implementation = function() {};
            console.log("[+] HttpsURLConnection." + m);
        } catch(_) {}
    });

    // SSLContext — replace TrustManager with trust-all
    try {
        const X509TM = Java.use("javax.net.ssl.X509TrustManager");
        const SSLCTX = Java.use("javax.net.ssl.SSLContext");
        const TM = Java.registerClass({
            name: "dev.bypass.TrustManager",
            implements: [X509TM],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {},
                getAcceptedIssuers: function() { return []; },
            }
        });
        const TMS = [TM.$new()];
        SSLCTX.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
        ).implementation = function(km, tm, sr) {
            SSLCTX.init.overload(
                "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
            ).call(this, km, TMS, sr);
        };
        console.log("[+] SSLContext (trust-all TrustManager)");
    } catch(e) { console.log("[ ] SSLContext"); }

    // TrustManagerImpl — Android 7+ network security config pinning
    try {
        const AL  = Java.use("java.util.ArrayList");
        const TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        try {
            TMI.checkTrustedRecursive.implementation = function() { return AL.$new(); };
        } catch(_) {}
        try {
            TMI.verifyChain.implementation = function(chain) { return chain; };
        } catch(_) {}
        console.log("[+] TrustManagerImpl");
    } catch(e) { console.log("[ ] TrustManagerImpl"); }

    // OkHttp3 — 4 overloads + obfuscated scan
    const OK3_OVERLOADS = [
        ["java.lang.String", "java.util.List"],
        ["java.lang.String", "java.security.cert.Certificate"],
        ["java.lang.String", "[Ljava.security.cert.Certificate;"],
    ];
    try {
        const CP3 = Java.use("okhttp3.CertificatePinner");
        OK3_OVERLOADS.forEach(sig => {
            try {
                CP3.check.overload(...sig).implementation = function() {};
            } catch(_) {}
        });
        try { CP3["check$okhttp"].implementation = function() {}; } catch(_) {}
        console.log("[+] OkHttp3 CertificatePinner");
    } catch(_) { console.log("[ ] OkHttp3 CertificatePinner"); }

    // Obfuscated OkHttp — only run the expensive scan when obfuscation is confirmed
    if (isObfuscated) {
        loadedClasses.forEach(cls => {
            if (cls.indexOf("CertificatePinner") >= 0 && cls.indexOf("okhttp3") < 0) {
                try {
                    const C = Java.use(cls);
                    if (C.check) {
                        OK3_OVERLOADS.forEach(sig => {
                            try { C.check.overload(...sig).implementation = function() {}; } catch(_) {}
                        });
                        console.log("[+] Obfuscated CertificatePinner: " + cls);
                    }
                } catch(_) {}
            }
        });
    }

    // OkHttp2 / Squareup
    try {
        const CP2 = Java.use("com.squareup.okhttp.CertificatePinner");
        try { CP2.check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function() {}; } catch(_) {}
        try { CP2.check.overload("java.lang.String", "java.util.List").implementation = function() {}; } catch(_) {}
        console.log("[+] OkHttp2 CertificatePinner");
    } catch(_) {}

    try {
        const OHV = Java.use("com.squareup.okhttp.internal.tls.OkHostnameVerifier");
        try { OHV.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function() { return true; }; } catch(_) {}
        try { OHV.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; }; } catch(_) {}
        console.log("[+] OkHttp2 OkHostnameVerifier");
    } catch(_) {}

    // Conscrypt CertPinManager
    try {
        const CPM = Java.use("com.android.org.conscrypt.CertPinManager");
        CPM.isChainValid.overload("java.lang.String", "java.util.List").implementation = function() { return true; };
        console.log("[+] Conscrypt CertPinManager");
    } catch(_) {}

    // CWAC-Netsecurity
    try {
        const CWAC = Java.use("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager");
        CWAC.isChainValid.overload("java.lang.String", "java.util.List").implementation = function() { return true; };
        console.log("[+] CWAC-Netsecurity CertPinManager");
    } catch(_) {}

    // OpenSSLSocketImpl — Conscrypt
    try {
        const OSSI = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
        OSSI.verifyCertificateChain.implementation = function() {};
        console.log("[+] OpenSSLSocketImpl Conscrypt");
    } catch(_) {}

    try {
        const OESI = Java.use("com.android.org.conscrypt.OpenSSLEngineSocketImpl");
        OESI.verifyCertificateChain.overload("[Ljava.lang.Long;", "java.lang.String")
            .implementation = function() {};
        console.log("[+] OpenSSLEngineSocketImpl Conscrypt");
    } catch(_) {}

    // OpenSSLSocketImpl — Apache Harmony (old AOSP)
    try {
        const OSSH = Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl");
        OSSH.verifyCertificateChain.implementation = function() {};
        console.log("[+] OpenSSLSocketImpl Apache Harmony");
    } catch(_) {}

    // Trustkit
    try {
        const TKV = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        try { TKV.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; }; } catch(_) {}
        try { TKV.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function() { return true; }; } catch(_) {}
        console.log("[+] Trustkit OkHostnameVerifier");
    } catch(_) {}

    try {
        const TKPTM = Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager");
        TKPTM.checkServerTrusted.implementation = function() {};
        console.log("[+] Trustkit PinningTrustManager");
    } catch(_) {}

    // Appmattus Certificate Transparency
    try {
        const CTI = Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor");
        CTI.intercept.implementation = function(chain) { return chain.proceed(chain.request()); };
        console.log("[+] Appmattus CertificateTransparencyInterceptor");
    } catch(_) {}

    try {
        const CTTM = Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager");
        try {
            CTTM.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String")
                .implementation = function() {};
        } catch(_) {}
        try {
            CTTM.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String")
                .implementation = function() { return Java.use("java.util.ArrayList").$new(); };
        } catch(_) {}
        console.log("[+] Appmattus CertificateTransparencyTrustManager");
    } catch(_) {}

    // WebViewClient — must call handler.proceed() or WebView hangs
    try {
        const WVC = Java.use("android.webkit.WebViewClient");
        WVC.onReceivedSslError.overload(
            "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"
        ).implementation = function(view, handler, error) { handler.proceed(); };
        console.log("[+] WebViewClient.onReceivedSslError");
    } catch(_) {}

    // Apache Cordova WebViewClient
    try {
        const CWV = Java.use("org.apache.cordova.CordovaWebViewClient");
        CWV.onReceivedSslError.overload(
            "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"
        ).implementation = function(view, handler, error) { handler.proceed(); };
        console.log("[+] Cordova CordovaWebViewClient");
    } catch(_) {}

    // Appcelerator Titanium
    try {
        const APPC = Java.use("appcelerator.https.PinningTrustManager");
        APPC.checkServerTrusted.implementation = function() {};
        console.log("[+] Appcelerator PinningTrustManager");
    } catch(_) {}

    // Netty
    try {
        const Netty = Java.use("io.netty.handler.ssl.util.FingerprintTrustManagerFactory");
        Netty.checkTrusted.implementation = function() {};
        console.log("[+] Netty FingerprintTrustManagerFactory");
    } catch(_) {}

    // Boye / Apache HTTP Client Android
    try {
        const Boye = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
        Boye.verify.implementation = function() {};
        console.log("[+] Boye AbstractVerifier");
    } catch(_) {}

    // IBM MobileFirst / WorkLight
    try {
        const WL = Java.use("com.worklight.wlclient.api.WLClient").getInstance();
        try { WL.pinTrustedCertificatePublicKey.overload("java.lang.String").implementation = function() {}; } catch(_) {}
        try { WL.pinTrustedCertificatePublicKey.overload("[Ljava.lang.String;").implementation = function() {}; } catch(_) {}
        console.log("[+] IBM MobileFirst pinTrustedCertificatePublicKey");
    } catch(_) {}

    try {
        const WLH = Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning");
        ["javax.net.ssl.SSLSocket", "java.security.cert.X509Certificate", "javax.net.ssl.SSLSession"].forEach(t => {
            try {
                WLH.verify.overload("java.lang.String", t).implementation = function() { return true; };
            } catch(_) {}
        });
        console.log("[+] IBM WorkLight HostNameVerifierWithCertificatePinning");
    } catch(_) {}

    // PhoneGap SSL checker
    try {
        const PG = Java.use("nl.xservices.plugins.sslCertificateChecker");
        PG.execute.overload(
            "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext"
        ).implementation = function() { return true; };
        console.log("[+] PhoneGap sslCertificateChecker");
    } catch(_) {}

    // Worklight Androidgap
    try {
        const WLGAP = Java.use("com.worklight.androidgap.plugin.WLCertificatePinningPlugin");
        WLGAP.execute.overload(
            "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext"
        ).implementation = function() { return true; };
        console.log("[+] Worklight Androidgap WLCertificatePinningPlugin");
    } catch(_) {}

    // ── 3j. Exit / crash traps ────────────────────────────────────────────────
    // Last. These must not interfere with the bypass hooks above.
    // We block self-kill. We do NOT print stack traces on exit —
    // Exception instantiation can be fingerprinted by the app.

    try {
        const System = Java.use("java.lang.System");
        System.exit.implementation = function(code) {
            console.log("[trap] System.exit(" + code + ") blocked");
            // Do not call original. App stays alive.
        };
        console.log("[+] System.exit trap");
    } catch(e) { console.log("[ ] System.exit trap"); }

    try {
        const RT2 = Java.use("java.lang.Runtime");
        RT2.halt.implementation = function(code) {
            console.log("[trap] Runtime.halt(" + code + ") blocked");
        };
        console.log("[+] Runtime.halt trap");
    } catch(e) { console.log("[ ] Runtime.halt trap"); }

    try {
        const AndroidProc = Java.use("android.os.Process");
        AndroidProc.killProcess.implementation = function(pid) {
            if (pid === AndroidProc.myPid()) {
                console.log("[trap] Process.killProcess(self) blocked");
                return;
            }
            return this.killProcess.call(this, pid);
        };
        console.log("[+] android.os.Process.killProcess trap");
    } catch(e) { console.log("[ ] Process.killProcess trap"); }

    // ── 3k. Play Integrity / SafetyNet — detection only ──────────────────────
    // These are JWS-signed server-side responses. Runtime hooking the Java
    // classes is insufficient — the nonce and signature are validated server-side.
    // If triggered, you need a static patch or a spoofed attestation response.
    // We hook the request initiation to log it so you know it's in play.
    try {
        const SNClient = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
        console.log("[!] SafetyNet detected — static patch required for full bypass");
    } catch(_) {}
    try {
        const PIManager = Java.use("com.google.android.play.core.integrity.IntegrityManager");
        console.log("[!] Play Integrity API detected — static patch required for full bypass");
    } catch(_) {}

    console.log("\n[*] All hooks installed.");
});

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║      Frida Universal Android Bypass — Intelligence-First Edition        ║
 * ║      Supports: Android 7–14 | Java / Flutter / RN / NDK                ║
 * ║      Bypass: SSL Pinning | Root Detection | Anti-Debug | Integrity      ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║  EXECUTION ORDER:                                                        ║
 * ║   Phase 0 — Intelligence & Recon (runs first, shapes all decisions)     ║
 * ║   Phase 1 — Anti-Detection Shield (Frida/hook hiding)                   ║
 * ║   Phase 2 — Environment Spoofing (root, emulator, build props)          ║
 * ║   Phase 3 — SSL/TLS Bypass (Java + Native + Flutter)                    ║
 * ║   Phase 4 — Stability Hooks (crash/exit traps, timing guards)           ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 0 — INTELLIGENCE & RECON ENGINE
// Runs synchronously before any bypass. Results drive hook strategy decisions.
// ═══════════════════════════════════════════════════════════════════════════════

const INTEL = {
    // ── 0.1 App Architecture ──────────────────────────────────────────────────
    arch: {
        isFlutter:       false,
        isReactNative:   false,
        isNativeHeavy:   false,
        isJavaPure:      true,   // default assumption, overridden below
        confidence:      {}
    },

    // ── 0.2 Network Stack ─────────────────────────────────────────────────────
    network: {
        hasOkHttp3:      false,
        hasOkHttp2:      false,   // com.squareup.okhttp (pre-v3)
        hasRetrofit:     false,
        hasVolley:       false,
        hasWebView:      false,
        hasNativeTLS:    false,   // libssl.so / libcrypto.so direct
        hasCustomStack:  false,
    },

    // ── 0.3 SSL Pinning Type ──────────────────────────────────────────────────
    pinning: {
        hasJavaPinning:    false,
        hasNativePinning:  false,
        hasCTPinning:      false,   // Certificate Transparency
        hasNetworkConfig:  false,   // res/xml/network_security_config
        hasCustomPinning:  false,
        isObfuscated:      false,
    },

    // ── 0.4 Obfuscation Level ─────────────────────────────────────────────────
    obfuscation: {
        hasProGuard:      false,
        hasR8:            false,
        hasDexGuard:      false,
        hasDynamicLoad:   false,   // DexClassLoader, PathClassLoader at runtime
        level:            "none",  // none / light / moderate / heavy
    },

    // ── 0.5 Root Detection Methods ────────────────────────────────────────────
    rootDetection: {
        checksFiles:      false,
        checksPackages:   false,
        checksProps:      false,
        checksSELinux:    false,
        checksNativeStat: false,
        checksProcesses:  false,
    },

    // ── 0.6 Frida / Hook Detection ────────────────────────────────────────────
    fridaDetection: {
        checksMaps:       false,   // /proc/self/maps scan for frida-agent
        checksPtrace:     false,   // ptrace(PTRACE_TRACEME) self-check
        checksThreads:    false,   // frida thread names (gmain, gdbus, pool-frida)
        checksStrings:    false,   // memory string scan for "LIBFRIDA"
        checksPort:       false,   // TCP 27042 Frida default port probe
    },

    // ── 0.7 Anti-Debug Mechanisms ─────────────────────────────────────────────
    antiDebug: {
        usesPtrace:       false,
        checksDebugger:   false,   // android.os.Debug.isDebuggerConnected()
        usesTiming:       false,   // timing delta attacks
        checksTracerPid:  false,   // /proc/self/status TracerPid check
        checksIsDebuggable: false, // ApplicationInfo.FLAG_DEBUGGABLE
    },

    // ── 0.8 Native Libraries ──────────────────────────────────────────────────
    nativeLibs: {
        all:            [],
        hasLibSSL:      false,
        hasLibCrypto:   false,
        hasLibFlutter:  false,
        hasHermes:      false,     // React Native Hermes engine
        hasCustomSec:   [],        // unknown .so files with security-sounding names
    },

    // ── 0.9 Execution Timing ──────────────────────────────────────────────────
    timing: {
        onStartup:      false,
        onLogin:        false,
        onAPICall:      false,
        onBackground:   false,
    },

    // ── 0.10 Exit / Crash Points ─────────────────────────────────────────────
    exitPoints: {
        usesSystemExit:   false,
        usesKill:         false,
        usesNativeCrash:  false,
        usesException:    false,
    },

    // ── 0.11 Integrity / Tamper Protection ───────────────────────────────────
    integrity: {
        checksSignature:  false,
        checksChecksum:   false,
        usesPlayIntegrity: false,  // Google Play Integrity API (successor to SafetyNet)
        usesSafetyNet:    false,   // Legacy SafetyNet
    },

    // ── 0.12 Environment Checks ───────────────────────────────────────────────
    environment: {
        checksEmulator:   false,
        checksBootloader: false,
        checksFingerprint: false,
        checksBuildProps: false,
    },

    // ── Strategy Decisions (populated after recon) ────────────────────────────
    strategy: {
        hookMode:         "java",        // java | native | hybrid
        bypassMethod:     "frida",       // frida | static | hybrid
        hookSurface:      [],            // list of active hook targets
        executionOrder:   [],            // ordered list of phases to run
        needsFallback:    false,
        fallbackReason:   "",
        skipHooks:        [],            // hooks to skip (not present in this app)
    },

    // ── Logging config ────────────────────────────────────────────────────────
    logging: {
        logSSLFailures:     true,
        logClassLoad:       false,      // too noisy unless obfuscation detected
        logDetectionEvents: true,
        logNativeHooks:     true,
        verbose:            false,
    }
};

// ─── Recon: Native library scan (synchronous, no Java.perform needed) ─────────
function recon_NativeLibs() {
    try {
        Process.enumerateModules().forEach(function(mod) {
            const name = mod.name.toLowerCase();
            INTEL.nativeLibs.all.push(mod.name);

            if (name === "libflutter.so") {
                INTEL.nativeLibs.hasLibFlutter = true;
                INTEL.arch.isFlutter = true;
                INTEL.arch.isJavaPure = false;
                INTEL.arch.confidence["flutter"] = "libflutter.so loaded";
            }
            if (name === "libhermes.so" || name === "libjsc.so") {
                INTEL.nativeLibs.hasHermes = true;
                INTEL.arch.isReactNative = true;
                INTEL.arch.isJavaPure = false;
                INTEL.arch.confidence["rn"] = name + " loaded";
            }
            if (name === "libreact_nativemodule_core.so" || name === "libreactnativejni.so") {
                INTEL.arch.isReactNative = true;
                INTEL.arch.isJavaPure = false;
            }
            if (name === "libssl.so") {
                INTEL.nativeLibs.hasLibSSL = true;
                INTEL.network.hasNativeTLS = true;
                INTEL.pinning.hasNativePinning = true;
            }
            if (name === "libcrypto.so") {
                INTEL.nativeLibs.hasLibCrypto = true;
            }
            // Flag unknown security-sounding libs for manual review
            if ((name.indexOf("ssl") >= 0 || name.indexOf("sec") >= 0 ||
                 name.indexOf("pin") >= 0 || name.indexOf("cert") >= 0) &&
                name !== "libssl.so" && name !== "libcrypto.so") {
                INTEL.nativeLibs.hasCustomSec.push(mod.name);
                INTEL.network.hasCustomStack = true;
            }
        });

        // If more than 5 .so files and no known framework — probably native-heavy
        const unknownNative = INTEL.nativeLibs.all.filter(n =>
            !["libflutter.so","libhermes.so","libjsc.so","libssl.so","libcrypto.so",
              "libc.so","libm.so","libdl.so","libz.so","libart.so"].includes(n.toLowerCase())
        );
        if (unknownNative.length > 5 && !INTEL.arch.isFlutter && !INTEL.arch.isReactNative) {
            INTEL.arch.isNativeHeavy = true;
            INTEL.arch.isJavaPure = false;
        }
    } catch(e) {
        console.log("[INTEL] Native lib scan error: " + e);
    }
}

// ─── Recon: /proc/self/maps analysis ──────────────────────────────────────────
function recon_ProcMaps() {
    try {
        const fd = new File("/proc/self/maps", "r");
        if (!fd) return;
        let line;
        const fridaIndicators = ["frida", "gadget", "agent", "linjector"];
        while ((line = fd.readLine()) !== null && line !== "") {
            const lower = line.toLowerCase();
            fridaIndicators.forEach(function(ind) {
                if (lower.indexOf(ind) >= 0) {
                    INTEL.fridaDetection.checksMaps = true; // app likely checks this too
                }
            });
        }
        fd.close();
    } catch(e) {
        // /proc/self/maps read can fail — not critical
    }
}

// ─── Recon: /proc/self/status for TracerPid ───────────────────────────────────
function recon_TracerPid() {
    try {
        const fd = new File("/proc/self/status", "r");
        if (!fd) return;
        let line;
        while ((line = fd.readLine()) !== null && line !== "") {
            if (line.indexOf("TracerPid") >= 0) {
                const val = parseInt(line.split(":")[1].trim());
                if (val > 0) {
                    INTEL.antiDebug.checksPtrace = true;
                }
            }
        }
        fd.close();
    } catch(e) {}
}

// ─── Recon: Java class enumeration (run inside Java.perform) ──────────────────
function recon_JavaClasses(loadedClasses) {
    const classStr = loadedClasses.join(",");

    // Network stack detection
    INTEL.network.hasOkHttp3   = classStr.indexOf("okhttp3.OkHttpClient") >= 0;
    INTEL.network.hasOkHttp2   = classStr.indexOf("com.squareup.okhttp.OkHttpClient") >= 0;
    INTEL.network.hasRetrofit  = classStr.indexOf("retrofit2.Retrofit") >= 0 ||
                                  classStr.indexOf("retrofit.RestAdapter") >= 0;
    INTEL.network.hasVolley    = classStr.indexOf("com.android.volley") >= 0;
    INTEL.network.hasWebView   = classStr.indexOf("android.webkit.WebView") >= 0;

    // SSL Pinning type detection
    INTEL.pinning.hasJavaPinning =
        classStr.indexOf("okhttp3.CertificatePinner") >= 0 ||
        classStr.indexOf("javax.net.ssl.TrustManager") >= 0 ||
        classStr.indexOf("com.datatheorem.android.trustkit") >= 0;
    INTEL.pinning.hasCTPinning =
        classStr.indexOf("com.appmattus.certificatetransparency") >= 0 ||
        classStr.indexOf("org.certificatetransparency") >= 0;
    INTEL.pinning.hasCustomPinning =
        classStr.indexOf("PinningTrustManager") >= 0 ||
        classStr.indexOf("CertificatePinner") >= 0;

    // Obfuscation detection — ProGuard/R8 produces single-letter class names
    let shortClassCount = 0;
    loadedClasses.forEach(function(cls) {
        const parts = cls.split(".");
        const simpleName = parts[parts.length - 1];
        if (simpleName.length <= 2 && /^[a-z]+$/.test(simpleName)) shortClassCount++;
    });
    if (shortClassCount > 200) {
        INTEL.obfuscation.hasProGuard = true;
        INTEL.obfuscation.level = shortClassCount > 800 ? "heavy" : "moderate";
        INTEL.pinning.isObfuscated = true;
        INTEL.logging.logClassLoad = true;  // enable class load logging when obfuscated
    }

    // Dynamic class loading detection
    INTEL.obfuscation.hasDynamicLoad =
        classStr.indexOf("dalvik.system.DexClassLoader") >= 0 ||
        classStr.indexOf("dalvik.system.InMemoryDexClassLoader") >= 0;

    // Root detection method detection
    INTEL.rootDetection.checksPackages =
        classStr.indexOf("android.app.PackageManager") >= 0;
    INTEL.rootDetection.checksProps =
        classStr.indexOf("android.os.SystemProperties") >= 0;

    // Anti-debug detection
    INTEL.antiDebug.checksDebugger =
        classStr.indexOf("android.os.Debug") >= 0;
    INTEL.antiDebug.checksIsDebuggable =
        classStr.indexOf("android.content.pm.ApplicationInfo") >= 0;

    // Integrity checks
    INTEL.integrity.usesPlayIntegrity =
        classStr.indexOf("com.google.android.play.core.integrity") >= 0;
    INTEL.integrity.usesSafetyNet =
        classStr.indexOf("com.google.android.gms.safetynet") >= 0;
    INTEL.integrity.checksSignature =
        classStr.indexOf("android.content.pm.PackageManager") >= 0;

    // Frida detection patterns
    INTEL.fridaDetection.checksThreads =
        classStr.indexOf("java.lang.Thread") >= 0;  // could be used to scan thread names

    // Environment checks
    INTEL.environment.checksEmulator =
        classStr.indexOf("android.os.Build") >= 0;
    INTEL.environment.checksBuildProps =
        classStr.indexOf("android.os.SystemProperties") >= 0;

    // Exit points
    INTEL.exitPoints.usesSystemExit =
        classStr.indexOf("java.lang.System") >= 0;
    INTEL.exitPoints.usesException =
        classStr.indexOf("java.lang.RuntimeException") >= 0;

    // React Native extra check via Java classes
    if (classStr.indexOf("com.facebook.react") >= 0 ||
        classStr.indexOf("com.facebook.soloader") >= 0) {
        INTEL.arch.isReactNative = true;
        INTEL.arch.isJavaPure = false;
        INTEL.arch.confidence["rn"] = "com.facebook.react class found";
    }
}

// ─── Strategy Resolver — runs after all recon ─────────────────────────────────
function resolveStrategy() {
    const s = INTEL.strategy;

    // Hook mode decision
    if (INTEL.arch.isFlutter && !INTEL.arch.isReactNative) {
        s.hookMode = "native";
        s.bypassMethod = "hybrid";  // pattern scan + native hook
    } else if (INTEL.arch.isNativeHeavy || INTEL.network.hasNativeTLS) {
        s.hookMode = "hybrid";
        s.bypassMethod = "hybrid";
    } else if (INTEL.arch.isReactNative) {
        s.hookMode = "hybrid";  // Java for React bridge + native for Hermes/JSC SSL
        s.bypassMethod = "frida";
    } else {
        s.hookMode = "java";
        s.bypassMethod = "frida";
    }

    // Fallback decision
    if (INTEL.obfuscation.level === "heavy" && !INTEL.network.hasNativeTLS) {
        s.needsFallback = true;
        s.fallbackReason = "Heavy obfuscation — Java class names unreliable, may need static patch";
    }
    if (INTEL.arch.isFlutter && !INTEL.nativeLibs.hasLibFlutter) {
        s.needsFallback = true;
        s.fallbackReason = "Flutter detected but libflutter.so not yet loaded — retry after app init";
    }

    // Hook surface — only enable what's actually present
    if (INTEL.network.hasOkHttp3)    s.hookSurface.push("okhttp3.CertificatePinner");
    if (INTEL.network.hasOkHttp2)    s.hookSurface.push("com.squareup.okhttp.CertificatePinner");
    if (INTEL.network.hasWebView)    s.hookSurface.push("WebViewClient");
    if (INTEL.network.hasRetrofit)   s.hookSurface.push("TrustManagerImpl");
    if (INTEL.nativeLibs.hasLibSSL)  s.hookSurface.push("libssl.SSL_CTX_set_verify");
    if (INTEL.nativeLibs.hasLibFlutter) s.hookSurface.push("libflutter.ssl_verify_peer_cert");
    if (INTEL.integrity.usesSafetyNet || INTEL.integrity.usesPlayIntegrity) {
        s.hookSurface.push("Play Integrity / SafetyNet");
    }

    // Execution order
    s.executionOrder = [
        "1. Anti-detection shield (maps, threads, ptrace)",
        "2. Environment spoof (root files, packages, build props)",
        "3. SSL/TLS bypass (" + s.hookMode + " mode)",
        "4. Integrity bypass (signature, SafetyNet/Play Integrity)",
        "5. Stability hooks (exit traps, crash guards)",
    ];

    // Logging strategy
    if (INTEL.pinning.isObfuscated) INTEL.logging.logClassLoad = true;
    if (INTEL.fridaDetection.checksMaps) INTEL.logging.verbose = true;
}

// ─── Print Intelligence Report ────────────────────────────────────────────────
function printIntelReport() {
    console.log("\n╔══════════════════════════════════════════════════════╗");
    console.log("║           INTELLIGENCE REPORT                        ║");
    console.log("╠══════════════════════════════════════════════════════╣");

    console.log("║ APP ARCHITECTURE                                      ║");
    console.log("║  Java/Dalvik pure   : " + pad(INTEL.arch.isJavaPure));
    console.log("║  Flutter            : " + pad(INTEL.arch.isFlutter));
    console.log("║  React Native       : " + pad(INTEL.arch.isReactNative));
    console.log("║  Native-heavy NDK   : " + pad(INTEL.arch.isNativeHeavy));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ NETWORK STACK                                         ║");
    console.log("║  OkHttp3            : " + pad(INTEL.network.hasOkHttp3));
    console.log("║  OkHttp2 (legacy)   : " + pad(INTEL.network.hasOkHttp2));
    console.log("║  Retrofit           : " + pad(INTEL.network.hasRetrofit));
    console.log("║  Volley             : " + pad(INTEL.network.hasVolley));
    console.log("║  WebView            : " + pad(INTEL.network.hasWebView));
    console.log("║  Native TLS (libssl): " + pad(INTEL.network.hasNativeTLS));
    console.log("║  Custom stack       : " + pad(INTEL.network.hasCustomStack));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ SSL PINNING TYPE                                      ║");
    console.log("║  Java-layer pinning : " + pad(INTEL.pinning.hasJavaPinning));
    console.log("║  Native pinning     : " + pad(INTEL.pinning.hasNativePinning));
    console.log("║  Cert Transparency  : " + pad(INTEL.pinning.hasCTPinning));
    console.log("║  Custom pinner      : " + pad(INTEL.pinning.hasCustomPinning));
    console.log("║  Obfuscated classes : " + pad(INTEL.pinning.isObfuscated));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ OBFUSCATION                                           ║");
    console.log("║  ProGuard/R8        : " + pad(INTEL.obfuscation.hasProGuard));
    console.log("║  DexGuard           : " + pad(INTEL.obfuscation.hasDexGuard));
    console.log("║  Dynamic loading    : " + pad(INTEL.obfuscation.hasDynamicLoad));
    console.log("║  Level              : " + INTEL.obfuscation.level);

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ ROOT DETECTION METHODS                                ║");
    console.log("║  File checks        : " + pad(INTEL.rootDetection.checksFiles));
    console.log("║  Package checks     : " + pad(INTEL.rootDetection.checksPackages));
    console.log("║  System props       : " + pad(INTEL.rootDetection.checksProps));
    console.log("║  SELinux checks     : " + pad(INTEL.rootDetection.checksSELinux));
    console.log("║  Native stat()      : " + pad(INTEL.rootDetection.checksNativeStat));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ FRIDA / HOOK DETECTION                                ║");
    console.log("║  /proc/maps scan    : " + pad(INTEL.fridaDetection.checksMaps));
    console.log("║  ptrace check       : " + pad(INTEL.fridaDetection.checksPtrace));
    console.log("║  Thread name scan   : " + pad(INTEL.fridaDetection.checksThreads));
    console.log("║  String scan        : " + pad(INTEL.fridaDetection.checksStrings));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ ANTI-DEBUG                                            ║");
    console.log("║  ptrace self-lock   : " + pad(INTEL.antiDebug.usesPtrace));
    console.log("║  isDebuggerConnected: " + pad(INTEL.antiDebug.checksDebugger));
    console.log("║  Timing attacks     : " + pad(INTEL.antiDebug.usesTiming));
    console.log("║  TracerPid check    : " + pad(INTEL.antiDebug.checksTracerPid));
    console.log("║  FLAG_DEBUGGABLE    : " + pad(INTEL.antiDebug.checksIsDebuggable));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ NATIVE LIBRARIES                                      ║");
    console.log("║  libssl.so          : " + pad(INTEL.nativeLibs.hasLibSSL));
    console.log("║  libcrypto.so       : " + pad(INTEL.nativeLibs.hasLibCrypto));
    console.log("║  libflutter.so      : " + pad(INTEL.nativeLibs.hasLibFlutter));
    console.log("║  libhermes.so       : " + pad(INTEL.nativeLibs.hasHermes));
    if (INTEL.nativeLibs.hasCustomSec.length > 0) {
        console.log("║  Custom security .so: " + INTEL.nativeLibs.hasCustomSec.join(", "));
    }

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ INTEGRITY / TAMPER PROTECTION                         ║");
    console.log("║  Signature check    : " + pad(INTEL.integrity.checksSignature));
    console.log("║  Play Integrity API : " + pad(INTEL.integrity.usesPlayIntegrity));
    console.log("║  SafetyNet (legacy) : " + pad(INTEL.integrity.usesSafetyNet));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ ENVIRONMENT CHECKS                                    ║");
    console.log("║  Emulator detect    : " + pad(INTEL.environment.checksEmulator));
    console.log("║  Bootloader check   : " + pad(INTEL.environment.checksBootloader));
    console.log("║  Build fingerprint  : " + pad(INTEL.environment.checksFingerprint));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ EXIT / CRASH POINTS                                   ║");
    console.log("║  System.exit()      : " + pad(INTEL.exitPoints.usesSystemExit));
    console.log("║  Native kill()      : " + pad(INTEL.exitPoints.usesKill));
    console.log("║  Native crash       : " + pad(INTEL.exitPoints.usesNativeCrash));

    console.log("╠══════════════════════════════════════════════════════╣");
    console.log("║ STRATEGY DECISION                                     ║");
    console.log("║  Hook mode          : " + INTEL.strategy.hookMode);
    console.log("║  Bypass method      : " + INTEL.strategy.bypassMethod);
    console.log("║  Hook surface       : " + INTEL.strategy.hookSurface.join(", "));
    if (INTEL.strategy.needsFallback) {
        console.log("║  ⚠ FALLBACK NEEDED  : " + INTEL.strategy.fallbackReason);
    }
    console.log("║ EXECUTION ORDER:");
    INTEL.strategy.executionOrder.forEach(function(step) {
        console.log("║    " + step);
    });
    console.log("╚══════════════════════════════════════════════════════╝\n");
}

function pad(val) {
    const s = val ? "YES" : "no ";
    return s + "                                              ║".substring(s.length);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROOT DETECTION DATA
// ═══════════════════════════════════════════════════════════════════════════════

const commonPaths = [
    "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/", "/sbin/su",
    "/system/app/Superuser.apk", "/system/bin/failsafe/su", "/system/bin/su",
    "/su/bin/su", "/system/etc/init.d/99SuperSUDaemon", "/system/sd/xbin/su",
    "/system/xbin/busybox", "/system/xbin/daemonsu", "/system/xbin/su",
    "/system/sbin/su", "/vendor/bin/su", "/cache/su", "/data/su", "/dev/su",
    "/system/bin/.ext/su", "/system/usr/we-need-root/su", "/system/app/Kinguser.apk",
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
];

const ROOTmanagementApp = [
    "com.noshufou.android.su", "com.noshufou.android.su.elite",
    "eu.chainfire.supersu", "eu.chainfire.supersu.pro",
    "com.koushikdutta.superuser", "com.thirdparty.superuser",
    "com.yellowes.su", "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch", "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus", "de.robv.android.xposed.installer",
    "com.saurik.substrate", "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot", "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium", "com.formyhm.hideroot",
    "me.phh.superuser", "com.kingouser.com", "com.topjohnwu.magisk",
    "me.weishu.kernelsu",           // KernelSU
    "com.bmax.raptor.superuser",    // APatch
    "io.github.huskydg.magisk",     // Magisk fork
    "com.github.androidadmin.kitsune",
];

const RootBinaries = [
    "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk",
    "magisk", "magisk64", "magiskpolicy", "magiskhide",
    "ksud", "ksu", "apd",
];

const RootProperties = {
    "ro.build.selinux": "1",
    "ro.debuggable": "0",
    "service.adb.root": "0",
    "ro.secure": "1"
};
const RootPropertiesKeys = Object.keys(RootProperties);

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1 — ANTI-DETECTION SHIELD
// Must run before everything else. Hides Frida presence.
// ═══════════════════════════════════════════════════════════════════════════════

function phase1_AntiDetection() {
    // 1a. Hide Frida threads from thread-name scans
    // Apps scan for: gmain, gdbus, pool-frida, gum-js-loop, frida
    try {
        const Thread = Java.use("java.lang.Thread");
        Thread.getName.implementation = function() {
            const name = this.getName.call(this);
            const lower = name.toLowerCase();
            if (lower.indexOf("frida") >= 0 || lower.indexOf("gum-js") >= 0 ||
                lower.indexOf("gmain") >= 0 || lower.indexOf("gdbus") >= 0 ||
                lower.indexOf("pool-frida") >= 0 || lower.indexOf("linjector") >= 0) {
                const fakeName = "Thread-" + Math.floor(Math.random() * 9999);
                log("AntiDetect", "Thread name hidden: " + name + " → " + fakeName);
                return fakeName;
            }
            return name;
        };
        console.log("[+] Thread name hiding");
    } catch(e) { console.log("[ ] Thread name hiding: " + e); }

    // 1b. Hide Frida from /proc/self/maps via BufferedReader
    try {
        const BufferedReader = Java.use("java.io.BufferedReader");
        const overload = BufferedReader.readLine.overload();
        overload.implementation = function() {
            let line = overload.call(this);
            if (line !== null) {
                const lower = line.toLowerCase();
                const fridaKeywords = ["frida", "gadget", "linjector", "gum-js", "zygisk", "lsplant", "ksu", "magisk"];
                for (const kw of fridaKeywords) {
                    if (lower.indexOf(kw) >= 0) {
                        log("AntiDetect", "/proc/maps line hidden: " + line.substring(0, 60));
                        return "";
                    }
                }
                // Also handle test-keys here
                if (line.indexOf("ro.build.tags=test-keys") >= 0) {
                    line = line.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }
            }
            return line;
        };
        console.log("[+] /proc/maps + BufferedReader filter");
    } catch(e) { console.log("[ ] BufferedReader filter: " + e); }

    // 1c. Defeat ptrace-based anti-debug (apps call ptrace(PTRACE_TRACEME) to lock debugger slot)
    //     We hook at native level — return 0 (success) so the app thinks it succeeded
    try {
        const ptrace = Module.findExportByName("libc.so", "ptrace");
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter(args) {
                    this.request = args[0].toInt32();
                    // PTRACE_TRACEME = 0, PTRACE_ATTACH = 16
                    if (this.request === 0 || this.request === 16) {
                        log("AntiDebug", "ptrace(" + this.request + ") intercepted");
                        this.fake = true;
                    }
                },
                onLeave(retval) {
                    if (this.fake) retval.replace(ptr(0));
                }
            });
            console.log("[+] ptrace anti-debug hook");
        }
    } catch(e) { console.log("[ ] ptrace hook: " + e); }

    // 1d. Defeat isDebuggerConnected() — used by app to kill itself if debugger found
    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            log("AntiDebug", "isDebuggerConnected() → false");
            return false;
        };
        console.log("[+] isDebuggerConnected bypass");
    } catch(e) { console.log("[ ] isDebuggerConnected: " + e); }

    // 1e. Defeat timing attacks — apps measure time delta of operations
    //     Wrap System.nanoTime / currentTimeMillis so delta is always small
    try {
        const System = Java.use("java.lang.System");
        let _nanoBase = null;
        System.nanoTime.implementation = function() {
            const real = this.nanoTime.call(this);
            if (_nanoBase === null) _nanoBase = real;
            // Compress time: make 1 real second look like ~10ms to defeat timing checks
            const compressed = _nanoBase + ((real - _nanoBase) / 100);
            return Math.floor(compressed);
        };
        console.log("[+] System.nanoTime timing attack mitigation");
    } catch(e) { console.log("[ ] nanoTime hook: " + e); }

    // 1f. Defeat /proc/self/status TracerPid check (native file read)
    const statusFopen = Module.findExportByName("libc.so", "fopen");
    // This is handled unified in phase2 native file hook below
    // Noted here for documentation of execution order

    // 1g. Disable FLAG_DEBUGGABLE check
    try {
        const ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        const FLAG_DEBUGGABLE = 2;
        // Override getApplicationInfo to clear debuggable flag
        // This is done via ActivityThread which holds the base context
        try {
            const ActivityThread = Java.use("android.app.ActivityThread");
            const currentApp = ActivityThread.currentApplication();
            if (currentApp !== null) {
                const appInfo = currentApp.getApplicationInfo();
                appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
                log("AntiDebug", "FLAG_DEBUGGABLE cleared from ApplicationInfo");
            }
        } catch(e2) {}
        console.log("[+] FLAG_DEBUGGABLE mitigation");
    } catch(e) { console.log("[ ] FLAG_DEBUGGABLE: " + e); }

    // 1h. Block Frida port probe — apps check TCP 27042
    try {
        const Socket = Java.use("java.net.Socket");
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            if (port === 27042 || port === 27043) {
                log("AntiDetect", "Frida port probe blocked: " + host + ":" + port);
                throw Java.use("java.net.ConnectException").$new("Connection refused");
            }
            return this.$init.overload('java.lang.String', 'int').call(this, host, port);
        };
        console.log("[+] Frida port 27042 probe block");
    } catch(e) { console.log("[ ] Frida port probe block: " + e); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2 — ENVIRONMENT SPOOFING
// Root files, packages, build props, emulator fingerprints, integrity
// ═══════════════════════════════════════════════════════════════════════════════

function phase2_Environment() {
    // 2a. Native file hooks (unified — single fopen attach, no duplicates)
    const fopen = Module.findExportByName("libc.so", "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter(args) {
                try {
                    this.inputPath = args[0].readUtf8String();
                    const shouldBlock =
                        commonPaths.indexOf(this.inputPath) >= 0 ||
                        this.inputPath.indexOf("magisk") >= 0 ||
                        this.inputPath.indexOf("/ksu") >= 0 ||
                        this.inputPath.indexOf("/adb/ap") >= 0 ||
                        // Block /proc/self/status TracerPid reads
                        (this.inputPath === "/proc/self/status");
                    if (shouldBlock) {
                        log("RootDetect", "fopen blocked: " + this.inputPath);
                        // Redirect /proc/self/status to a clean fake, block root paths
                        args[0].writeUtf8String("/notexists");
                        this.blocked = true;
                    }
                } catch(e) {}
            }
        });
        console.log("[+] Native fopen hook (unified)");
        INTEL.rootDetection.checksFiles = true;
    }

    // access()
    const accessFn = Module.findExportByName("libc.so", "access");
    if (accessFn) {
        Interceptor.attach(accessFn, {
            onEnter(args) {
                try { this.inputPath = args[0].readUtf8String(); } catch(e) { this.inputPath = ""; }
            },
            onLeave(retval) {
                const shouldBlock =
                    commonPaths.indexOf(this.inputPath) >= 0 ||
                    this.inputPath.indexOf("magisk") >= 0 ||
                    this.inputPath.indexOf("/ksu") >= 0 ||
                    this.inputPath.indexOf("/adb/ap") >= 0;
                if (retval.toInt32() === 0 && shouldBlock) {
                    log("RootDetect", "access() blocked: " + this.inputPath);
                    retval.replace(ptr(-1));
                    INTEL.rootDetection.checksNativeStat = true;
                }
            }
        });
        console.log("[+] Native access() hook");
    }

    // stat family
    ["stat", "__xstat", "stat64", "__xstat64"].forEach(function(fn) {
        try {
            const statFn = Module.findExportByName("libc.so", fn);
            if (!statFn) return;
            Interceptor.attach(statFn, {
                onEnter(args) {
                    const pathIdx = fn.startsWith("__x") ? 1 : 0;
                    try { this.inputPath = args[pathIdx].readUtf8String(); } catch(e) { this.inputPath = ""; }
                },
                onLeave(retval) {
                    const shouldBlock =
                        commonPaths.indexOf(this.inputPath) >= 0 ||
                        this.inputPath.indexOf("magisk") >= 0;
                    if (retval.toInt32() === 0 && shouldBlock) {
                        log("RootDetect", fn + "() blocked: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            });
        } catch(e) {}
    });
    console.log("[+] Native stat family hooks");

    // execve — native exec root check bypass
    try {
        const execve = Module.findExportByName("libc.so", "execve");
        if (execve) {
            Interceptor.attach(execve, {
                onEnter(args) {
                    try {
                        const cmd = args[0].readUtf8String();
                        if (cmd && (cmd.indexOf("su") !== -1 || cmd.indexOf("getprop") !== -1 ||
                            cmd.indexOf("magisk") !== -1 || cmd.indexOf("mount") !== -1)) {
                            log("RootDetect", "execve blocked: " + cmd);
                            args[0].writeUtf8String("/system/bin/grep");
                        }
                    } catch(e) {}
                }
            });
            console.log("[+] Native execve hook");
        }
    } catch(e) { console.log("[ ] execve: " + e); }

    // system()
    try {
        const systemFn = Module.findExportByName("libc.so", "system");
        if (systemFn) {
            Interceptor.attach(systemFn, {
                onEnter(args) {
                    try {
                        const cmd = args[0].readUtf8String();
                        if (cmd.indexOf("getprop") !== -1 || cmd === "mount" ||
                            cmd.indexOf("build.prop") !== -1 || cmd === "id" ||
                            cmd === "su" || cmd.indexOf("magisk") !== -1) {
                            log("RootDetect", "system() blocked: " + cmd);
                            args[0].writeUtf8String("grep");
                        }
                    } catch(e) {}
                }
            });
            console.log("[+] Native system() hook");
        }
    } catch(e) { console.log("[ ] system(): " + e); }

    // __system_property_get — native prop spoof
    try {
        const sysPropGet = Module.findExportByName("libc.so", "__system_property_get");
        if (sysPropGet) {
            Interceptor.attach(sysPropGet, {
                onEnter(args) {
                    this.key = args[0].readCString();
                    this.ret = args[1];
                },
                onLeave(ret) {
                    const fakeProps = {
                        "ro.build.fingerprint": "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys",
                        "ro.build.tags": "release-keys",
                        "ro.debuggable": "0",
                        "ro.secure": "1",
                        "service.adb.root": "0",
                        "ro.build.selinux": "1",
                        "ro.build.type": "user",
                    };
                    if (this.key && fakeProps[this.key]) {
                        const val = fakeProps[this.key];
                        const p = Memory.allocUtf8String(val);
                        Memory.copy(this.ret, p, val.length + 1);
                        INTEL.rootDetection.checksProps = true;
                    }
                }
            });
            console.log("[+] __system_property_get hook");
        }
    } catch(e) { console.log("[ ] __system_property_get: " + e); }
}

function phase2_JavaEnvironment() {
    // Java UnixFileSystem check
    try {
        const UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            const filename = file.getAbsolutePath();
            const shouldBlock =
                commonPaths.indexOf(filename) >= 0 ||
                filename.indexOf("magisk") >= 0 ||
                filename.indexOf("/ksu") >= 0 ||
                filename.indexOf("/adb/ap") >= 0;
            if (shouldBlock) {
                log("RootDetect", "Java checkAccess blocked: " + filename);
                return false;
            }
            return this.checkAccess(file, access);
        };
        console.log("[+] Java UnixFileSystem.checkAccess hook");
    } catch(e) { console.log("[ ] UnixFileSystem.checkAccess: " + e); }

    // File.exists
    try {
        const NativeFile = Java.use('java.io.File');
        NativeFile.exists.implementation = function() {
            const name = NativeFile.getName.call(this);
            if (RootBinaries.indexOf(name) > -1) {
                log("RootDetect", "File.exists() blocked: " + name);
                return false;
            }
            return this.exists.call(this);
        };
        console.log("[+] File.exists hook");
    } catch(e) { console.log("[ ] File.exists: " + e); }

    // Build fields spoof
    try {
        const Build = Java.use("android.os.Build");
        const spoofFields = { "TAGS": "release-keys", "TYPE": "user" };
        for (const [field, value] of Object.entries(spoofFields)) {
            try {
                const f = Build.class.getDeclaredField(field);
                f.setAccessible(true);
                f.set(null, value);
            } catch(e) {}
        }
        const FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT");
        FINGERPRINT.setAccessible(true);
        FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys");
        console.log("[+] Build fields spoofed");
        INTEL.environment.checksFingerprint = true;
    } catch(e) { console.log("[ ] Build field spoof: " + e); }

    // SystemProperties
    try {
        const SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function(name) {
            if (RootPropertiesKeys.indexOf(name) !== -1) {
                log("RootDetect", "SystemProperties.get blocked: " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };
        console.log("[+] SystemProperties.get hook");
        INTEL.rootDetection.checksProps = true;
    } catch(e) { console.log("[ ] SystemProperties.get: " + e); }

    // String.contains test-keys
    try {
        const Str = Java.use('java.lang.String');
        Str.contains.implementation = function(name) {
            if (name === "test-keys") {
                log("RootDetect", "test-keys check bypassed");
                return false;
            }
            return this.contains.call(this, name);
        };
        console.log("[+] String.contains (test-keys) hook");
    } catch(e) { console.log("[ ] String.contains: " + e); }

    // PackageManager — Android 13+ aware
    try {
        const APM = Java.use("android.app.ApplicationPackageManager");
        try {
            APM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
                if (ROOTmanagementApp.indexOf(str) >= 0) {
                    log("RootDetect", "getPackageInfo(int) blocked: " + str);
                    str = "not.found.fake.package";
                }
                return this.getPackageInfo(str, i);
            };
        } catch(e) {}
        // Android 13+ PackageInfoFlags overload
        try {
            APM.getPackageInfo.overload(
                'java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags'
            ).implementation = function(str, flags) {
                if (ROOTmanagementApp.indexOf(str) >= 0) {
                    log("RootDetect", "getPackageInfo(Flags/API33) blocked: " + str);
                    str = "not.found.fake.package";
                }
                return this.getPackageInfo(str, flags);
            };
            console.log("[+] getPackageInfo(PackageInfoFlags) hook — Android 13+");
        } catch(e) {}
        // getInstalledPackages
        try {
            APM.getInstalledPackages.overload('int').implementation = function(flags) {
                const pkgList = this.getInstalledPackages(flags);
                const iter = pkgList.iterator();
                while (iter.hasNext()) {
                    const pkgInfo = iter.next();
                    const pname = pkgInfo.packageName.value;
                    if (ROOTmanagementApp.indexOf(pname) >= 0) {
                        log("RootDetect", "getInstalledPackages removed: " + pname);
                        iter.remove();
                    }
                }
                return pkgList;
            };
        } catch(e) {}
        console.log("[+] PackageManager hooks (all overloads)");
        INTEL.rootDetection.checksPackages = true;
    } catch(e) { console.log("[ ] PackageManager hooks: " + e); }

    // Runtime.exec family
    try {
        const Runtime = Java.use('java.lang.Runtime');
        const suspectCmds = ["su", "getprop", "mount", "build.prop", "id", "sh", "magisk", "ksud"];
        function isSuspect(cmd) { return suspectCmds.some(s => cmd.indexOf(s) !== -1); }
        function fakeCmd(cmd) { return (cmd === "su" || cmd.indexOf("magisk") !== -1) ? "justafakecommand" : "grep"; }
        [
            Runtime.exec.overload('java.lang.String'),
            Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;'),
            Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File'),
        ].forEach(function(overload) {
            try {
                overload.implementation = function() {
                    const cmd = arguments[0];
                    const c = typeof cmd === 'string' ? cmd : (cmd ? cmd.toString() : "");
                    if (isSuspect(c)) {
                        log("RootDetect", "Runtime.exec blocked: " + c);
                        return Runtime.exec.overload('java.lang.String').call(this, fakeCmd(c));
                    }
                    return overload.apply(this, arguments);
                };
            } catch(e) {}
        });
        console.log("[+] Runtime.exec family hooks");
    } catch(e) { console.log("[ ] Runtime.exec: " + e); }

    // ProcessBuilder
    try {
        const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function() {
            const cmd = this.command.call(this);
            for (let i = 0; i < cmd.size(); i++) {
                const c = cmd.get(i).toString();
                if (["getprop","mount","build.prop","id","su","magisk"].some(s => c.indexOf(s) !== -1)) {
                    log("RootDetect", "ProcessBuilder blocked: " + cmd);
                    this.command.call(this, ["grep"]);
                    return this.start.call(this);
                }
            }
            return this.start.call(this);
        };
        console.log("[+] ProcessBuilder.start hook");
    } catch(e) { console.log("[ ] ProcessBuilder.start: " + e); }

    // ProcessImpl (guarded — not present on all Android versions)
    const loaded = Java.enumerateLoadedClassesSync();
    if (loaded.indexOf('java.lang.ProcessImpl') !== -1) {
        try {
            const Str = Java.use('java.lang.String');
            const ProcessImpl = Java.use("java.lang.ProcessImpl");
            ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
                const cmd0 = cmdarray[0] || "";
                const cmd1 = cmdarray.length > 1 ? cmdarray[1] : "";
                const blockConditions = [
                    cmd0 === "mount", cmd0 === "id",
                    cmd0 === "su", cmd0.indexOf("magisk") >= 0,
                    (cmd0 === "getprop" && ["ro.secure","ro.debuggable","ro.build.tags"].indexOf(cmd1) >= 0),
                    (cmd0.indexOf("which") >= 0 && cmd1 === "su"),
                ];
                if (blockConditions.some(Boolean)) {
                    log("RootDetect", "ProcessImpl blocked: " + cmdarray.toString());
                    arguments[0] = Java.array('java.lang.String', [Str.$new("justafakecommand")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
                return ProcessImpl.start.apply(this, arguments);
            };
            console.log("[+] ProcessImpl.start hook");
        } catch(e) { console.log("[ ] ProcessImpl.start: " + e); }
    }

    // Play Integrity / SafetyNet bypass
    if (INTEL.integrity.usesPlayIntegrity || INTEL.integrity.usesSafetyNet) {
        try {
            // SafetyNet — hook the verify response
            const SafetyNetHelper = Java.use("com.google.android.gms.safetynet.SafetyNetApi");
            if (SafetyNetHelper) {
                console.log("[!] SafetyNet detected — response hook needed (JWS level, static patch recommended)");
            }
        } catch(e) {}
    }

    // Emulator detection bypass
    try {
        const Build = Java.use("android.os.Build");
        // Spoof MANUFACTURER, MODEL, BRAND to real device values
        const emuSpoofs = {
            "MANUFACTURER": "Google",
            "MODEL": "Pixel 5",
            "BRAND": "google",
            "DEVICE": "redfin",
            "PRODUCT": "redfin",
            "HARDWARE": "redfin",
        };
        for (const [field, value] of Object.entries(emuSpoofs)) {
            try {
                const f = Build.class.getDeclaredField(field);
                f.setAccessible(true);
                f.set(null, value);
            } catch(e2) {}
        }
        console.log("[+] Emulator/Build fields spoofed");
        INTEL.environment.checksEmulator = true;
    } catch(e) { console.log("[ ] Emulator spoof: " + e); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 3 — SSL / TLS BYPASS
// Strategy-aware: Java, Native, Flutter, obfuscated OkHttp
// ═══════════════════════════════════════════════════════════════════════════════

function phase3_NativeSSL() {
    // SSL_CTX_set_verify
    try {
        const libssl = Process.findModuleByName("libssl.so");
        if (libssl) {
            const fn = libssl.findExportByName("SSL_CTX_set_verify");
            if (fn) {
                Interceptor.attach(fn, {
                    onEnter(args) {
                        args[1] = ptr(0); // SSL_VERIFY_NONE
                        args[2] = ptr(0); // null callback
                        log("SSL", "SSL_CTX_set_verify neutered");
                    }
                });
                console.log("[+] SSL_CTX_set_verify (native libssl)");
            }
        }
    } catch(e) { console.log("[ ] SSL_CTX_set_verify: " + e); }

    // X509_verify_cert
    try {
        const libcrypto = Process.findModuleByName("libcrypto.so");
        if (libcrypto) {
            const fn = libcrypto.findExportByName("X509_verify_cert");
            if (fn) {
                Interceptor.attach(fn, {
                    onLeave(retval) {
                        if (retval.toInt32() !== 1) {
                            retval.replace(ptr(1));
                            log("SSL", "X509_verify_cert forced success");
                        }
                    }
                });
                console.log("[+] X509_verify_cert (native libcrypto)");
            }
        }
    } catch(e) { console.log("[ ] X509_verify_cert: " + e); }
}

function phase3_FlutterSSL() {
    if (!INTEL.nativeLibs.hasLibFlutter) {
        console.log("[ ] Flutter SSL bypass skipped (libflutter.so not loaded)");
        return;
    }
    try {
        const flutter = Process.getModuleByName("libflutter.so");
        // arm64 prologue pattern for ssl_verify_peer_cert (Flutter 3.x stable)
        const pattern = "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9";
        Memory.scan(flutter.base, flutter.size, pattern, {
            onMatch(address) {
                log("SSL", "Flutter ssl_verify_peer_cert at " + address);
                Interceptor.attach(address, {
                    onLeave(retval) {
                        retval.replace(ptr(0)); // SSL_VERIFY_OK
                        log("SSL", "Flutter SSL verify bypassed");
                    }
                });
            },
            onError(r) { console.log("[ ] Flutter pattern scan error: " + r); },
            onComplete() {}
        });
        // Secondary path — newer Flutter versions
        try {
            const fn = flutter.findExportByName("ssl_crypto_x509_session_verify_cert_chain");
            if (fn) {
                Interceptor.attach(fn, {
                    onLeave(retval) {
                        retval.replace(ptr(1));
                        log("SSL", "Flutter ssl_crypto_x509_session_verify_cert_chain bypassed");
                    }
                });
                console.log("[+] Flutter ssl_crypto_x509_session_verify_cert_chain");
            }
        } catch(e) {}
        console.log("[+] Flutter SSL bypass (pattern scan initiated)");
    } catch(e) { console.log("[ ] Flutter SSL: " + e); }
}

function phase3_JavaSSL() {
    // SSLPeerUnverifiedException auto-patcher
    try {
        const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
        UnverifiedCertError.$init.implementation = function(str) {
            log("SSL", "SSLPeerUnverifiedException thrown — attempting auto-patch");
            try {
                const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                const idx = stackTrace.findIndex(s => s.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException");
                const caller = stackTrace[idx + 1];
                const className = caller.getClassName();
                const methodName = caller.getMethodName();
                log("SSL", "Thrown by " + className + "->" + methodName);
                const callingClass = Java.use(className);
                const callingMethod = callingClass[methodName];
                if (!callingMethod.implementation) {
                    const returnType = callingMethod.returnType.type;
                    callingMethod.implementation = function() {
                        log("SSL", "Auto-patched " + className + "->" + methodName);
                        return returnType === 'void' ? undefined : null;
                    };
                }
            } catch(e) { log("SSL", "Auto-patch failed: " + e); }
            return this.$init(str);
        };
        console.log('[+] SSLPeerUnverifiedException auto-patcher');
    } catch(e) { console.log('[ ] SSLPeerUnverifiedException auto-patcher'); }

    // HttpsURLConnection
    ["setDefaultHostnameVerifier","setSSLSocketFactory","setHostnameVerifier"].forEach(function(method) {
        try {
            const HUC = Java.use("javax.net.ssl.HttpsURLConnection");
            HUC[method].implementation = function() {
                log("SSL", "HttpsURLConnection." + method + " bypassed");
            };
            console.log("[+] HttpsURLConnection." + method);
        } catch(e) { console.log("[ ] HttpsURLConnection." + method); }
    });

    // SSLContext — custom trust-all TrustManager
    try {
        const X509TM = Java.use('javax.net.ssl.X509TrustManager');
        const SSLCtx = Java.use('javax.net.ssl.SSLContext');
        const TrustManager = Java.registerClass({
            name: 'dev.asd.test.TrustManager',
            implements: [X509TM],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        const TrustManagers = [TrustManager.$new()];
        SSLCtx.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        ).implementation = function(km, tm, sr) {
            log("SSL", "SSLContext.init bypassed");
            SSLCtx.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
            ).call(this, km, TrustManagers, sr);
        };
        console.log('[+] SSLContext');
    } catch(e) { console.log('[ ] SSLContext: ' + e); }

    // TrustManagerImpl (Android 7+)
    try {
        const al = Java.use("java.util.ArrayList");
        const TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMI.checkTrustedRecursive.implementation = function() {
            log("SSL", "TrustManagerImpl.checkTrustedRecursive bypassed");
            return al.$new();
        };
        TMI.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host) {
            log("SSL", "TrustManagerImpl.verifyChain bypassed: " + host);
            return untrustedChain;
        };
        console.log('[+] TrustManagerImpl');
    } catch(e) { console.log('[ ] TrustManagerImpl'); }

    // OkHTTP3
    const okhttp3Overloads = [
        ['java.lang.String', 'java.util.List'],
        ['java.lang.String', 'java.security.cert.Certificate'],
        ['java.lang.String', '[Ljava.security.cert.Certificate;'],
    ];
    okhttp3Overloads.forEach(function(sig) {
        try {
            const CP = Java.use('okhttp3.CertificatePinner');
            CP.check.overload(...sig).implementation = function(a) {
                log("SSL", "OkHTTP3 CertificatePinner.check bypassed: " + a);
            };
            console.log("[+] OkHTTP3 CertificatePinner (" + sig[1] + ")");
        } catch(e) { console.log("[ ] OkHTTP3 (" + (sig[1] || sig) + ")"); }
    });
    try {
        const CP = Java.use('okhttp3.CertificatePinner');
        CP['check$okhttp'].implementation = function(a) {
            log("SSL", "OkHTTP3 check$okhttp bypassed: " + a);
        };
        console.log('[+] OkHTTPv3 ($okhttp)');
    } catch(e) { console.log('[ ] OkHTTPv3 ($okhttp)'); }

    // Obfuscated OkHttp dynamic scan (only when obfuscation detected)
    if (INTEL.obfuscation.hasProGuard || INTEL.pinning.isObfuscated) {
        try {
            const classes = Java.enumerateLoadedClassesSync();
            classes.forEach(function(cls) {
                if (cls.indexOf("CertificatePinner") >= 0 && cls.indexOf("okhttp3") < 0) {
                    try {
                        const Cls = Java.use(cls);
                        if (Cls.check) {
                            Cls.check.overload('java.lang.String', 'java.util.List').implementation = function(a) {
                                log("SSL", "Obfuscated CertificatePinner bypassed: " + cls);
                            };
                            console.log("[+] Obfuscated CertificatePinner: " + cls);
                        }
                    } catch(e) {}
                }
            });
        } catch(e) { console.log("[ ] Obfuscated OkHttp scan: " + e); }
    }

    // OpenSSLSocketImpl Conscrypt
    try {
        const OSI = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OSI.verifyCertificateChain.implementation = function() {
            log("SSL", "OpenSSLSocketImpl.verifyCertificateChain bypassed");
        };
        console.log('[+] OpenSSLSocketImpl Conscrypt');
    } catch(e) { console.log('[ ] OpenSSLSocketImpl Conscrypt'); }

    try {
        const OESI = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
        OESI.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(a, b) {
            log("SSL", "OpenSSLEngineSocketImpl bypassed: " + b);
        };
        console.log('[+] OpenSSLEngineSocketImpl Conscrypt');
    } catch(e) { console.log('[ ] OpenSSLEngineSocketImpl Conscrypt'); }

    try {
        const OSIH = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
        OSIH.verifyCertificateChain.implementation = function() {
            log("SSL", "OpenSSLSocketImpl Apache Harmony bypassed");
        };
        console.log('[+] OpenSSLSocketImpl Apache Harmony');
    } catch(e) { console.log('[ ] OpenSSLSocketImpl Apache Harmony'); }

    // Trustkit
    try {
        const tk = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        tk.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a) { return true; };
        tk.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a) { return true; };
        console.log('[+] Trustkit OkHostnameVerifier');
    } catch(e) { console.log('[ ] Trustkit OkHostnameVerifier'); }

    try {
        const tkPTM = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        tkPTM.checkServerTrusted.implementation = function() { log("SSL", "Trustkit PinningTrustManager bypassed"); };
        console.log('[+] Trustkit PinningTrustManager');
    } catch(e) { console.log('[ ] Trustkit PinningTrustManager'); }

    // Appmattus CT
    try {
        const CTI = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor');
        CTI['intercept'].implementation = function(a) {
            log("SSL", "Appmattus CertificateTransparencyInterceptor bypassed");
            return a.proceed(a.request());
        };
        console.log('[+] Appmattus CertificateTransparencyInterceptor');
    } catch(e) { console.log('[ ] Appmattus CertificateTransparencyInterceptor'); }

    try {
        const CTTM = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager');
        CTTM['checkServerTrusted'].overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String')
            .implementation = function() { log("SSL", "Appmattus CTTM [2-arg] bypassed"); };
        CTTM['checkServerTrusted'].overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String')
            .implementation = function() {
                log("SSL", "Appmattus CTTM [3-arg] bypassed");
                return Java.use('java.util.ArrayList').$new();
            };
        console.log('[+] Appmattus CertificateTransparencyTrustManager');
    } catch(e) { console.log('[ ] Appmattus CTTM'); }

    // Conscrypt CertPinManager
    try {
        const CPM = Java.use('com.android.org.conscrypt.CertPinManager');
        CPM.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a) {
            log("SSL", "Conscrypt CertPinManager bypassed: " + a);
            return true;
        };
        console.log('[+] Conscrypt CertPinManager');
    } catch(e) { console.log('[ ] Conscrypt CertPinManager'); }

    // CWAC-Netsecurity
    try {
        const CWAC = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
        CWAC.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a) { return true; };
        console.log('[+] CWAC-Netsecurity CertPinManager');
    } catch(e) { console.log('[ ] CWAC-Netsecurity CertPinManager'); }

    // Squareup OkHTTP v2
    try {
        const SQ = Java.use('com.squareup.okhttp.CertificatePinner');
        SQ.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a) { return; };
        SQ.check.overload('java.lang.String', 'java.util.List').implementation = function(a) { return; };
        console.log('[+] Squareup CertificatePinner (OkHTTP v2)');
    } catch(e) { console.log('[ ] Squareup CertificatePinner'); }

    try {
        const SQH = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        SQH.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function() { return true; };
        SQH.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() { return true; };
        console.log('[+] Squareup OkHostnameVerifier');
    } catch(e) { console.log('[ ] Squareup OkHostnameVerifier'); }

    // WebViewClient
    try {
        const WVC = Java.use('android.webkit.WebViewClient');
        WVC.onReceivedSslError.overload(
            'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'
        ).implementation = function(v, handler, error) {
            log("SSL", "WebViewClient.onReceivedSslError bypassed");
            handler.proceed();
        };
        console.log('[+] Android WebViewClient (SslErrorHandler)');
    } catch(e) { console.log('[ ] Android WebViewClient'); }

    // Cordova
    try {
        const CWV = Java.use('org.apache.cordova.CordovaWebViewClient');
        CWV.onReceivedSslError.overload(
            'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'
        ).implementation = function(v, handler, error) {
            log("SSL", "Cordova WebViewClient bypassed");
            handler.proceed();
        };
        console.log('[+] Apache Cordova WebViewClient');
    } catch(e) { console.log('[ ] Cordova WebViewClient'); }

    // Appcelerator
    try {
        const APPC = Java.use('appcelerator.https.PinningTrustManager');
        APPC.checkServerTrusted.implementation = function() { log("SSL", "Appcelerator bypassed"); };
        console.log('[+] Appcelerator PinningTrustManager');
    } catch(e) { console.log('[ ] Appcelerator'); }

    // IBM MobileFirst + WorkLight
    try {
        const WL = Java.use('com.worklight.wlclient.api.WLClient');
        WL.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function() {};
        WL.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function() {};
        console.log('[+] IBM MobileFirst');
    } catch(e) { console.log('[ ] IBM MobileFirst'); }

    // Netty
    try {
        const Netty = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
        Netty.checkTrusted.implementation = function() { log("SSL", "Netty FingerprintTrustManagerFactory bypassed"); };
        console.log('[+] Netty FingerprintTrustManagerFactory');
    } catch(e) { console.log('[ ] Netty'); }

    // Boye
    try {
        const Boye = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
        Boye.verify.implementation = function(host) { log("SSL", "Boye AbstractVerifier bypassed: " + host); };
        console.log('[+] Boye AbstractVerifier');
    } catch(e) { console.log('[ ] Boye'); }

    // PhoneGap
    try {
        const PG = Java.use('nl.xservices.plugins.sslCertificateChecker');
        PG.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext')
            .implementation = function() { return true; };
        console.log('[+] PhoneGap sslCertificateChecker');
    } catch(e) { console.log('[ ] PhoneGap'); }

    // Worklight Androidgap
    try {
        const WLAG = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
        WLAG.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext')
            .implementation = function() { return true; };
        console.log('[+] Worklight Androidgap WLCertificatePinningPlugin');
    } catch(e) { console.log('[ ] Worklight Androidgap'); }

    // CWAC-Netsecurity
    try {
        const CWAC2 = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
        CWAC2.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function() { return true; };
        console.log('[+] CWAC-Netsecurity CertPinManager');
    } catch(e) { console.log('[ ] CWAC-Netsecurity 2'); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 4 — STABILITY HOOKS
// Trap crash/exit points, log detection trigger moments
// ═══════════════════════════════════════════════════════════════════════════════

function phase4_Stability() {
    // 4a. Trap System.exit — apps call this when they detect tampering
    try {
        const System = Java.use("java.lang.System");
        System.exit.implementation = function(code) {
            console.log("[!!!] System.exit(" + code + ") called — BLOCKED");
            console.log("[!!!] Stack at exit:");
            stackTraceHere(true);
            // Do NOT call this.exit() — we want to keep the app alive
        };
        console.log("[+] System.exit trap");
        INTEL.exitPoints.usesSystemExit = true;
    } catch(e) { console.log("[ ] System.exit trap: " + e); }

    // 4b. Trap Runtime.halt (harder kill)
    try {
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.halt.implementation = function(code) {
            console.log("[!!!] Runtime.halt(" + code + ") called — BLOCKED");
        };
        console.log("[+] Runtime.halt trap");
    } catch(e) { console.log("[ ] Runtime.halt trap: " + e); }

    // 4c. Native kill() — Process.killProcess, android.os.Process.killProcess
    try {
        const Proc = Java.use("android.os.Process");
        Proc.killProcess.implementation = function(pid) {
            const myPid = Proc.myPid();
            if (pid === myPid) {
                console.log("[!!!] android.os.Process.killProcess(self) BLOCKED");
                return;
            }
            return this.killProcess.call(this, pid);
        };
        console.log("[+] android.os.Process.killProcess trap");
        INTEL.exitPoints.usesKill = true;
    } catch(e) { console.log("[ ] Process.killProcess trap: " + e); }

    // 4d. Native kill() syscall
    try {
        const kill = Module.findExportByName("libc.so", "kill");
        if (kill) {
            Interceptor.attach(kill, {
                onEnter(args) {
                    const pid = args[0].toInt32();
                    const sig = args[1].toInt32();
                    if (pid === Process.id && (sig === 9 || sig === 6)) {
                        console.log("[!!!] Native kill(" + pid + ", " + sig + ") on self — BLOCKED");
                        args[1] = ptr(0); // Replace with signal 0 (no-op)
                        INTEL.exitPoints.usesNativeCrash = true;
                    }
                }
            });
            console.log("[+] Native kill() trap");
        }
    } catch(e) { console.log("[ ] Native kill() trap: " + e); }

    // 4e. Trap raise() — used for SIGABRT/SIGSEGV intentional crashes
    try {
        const raise = Module.findExportByName("libc.so", "raise");
        if (raise) {
            Interceptor.attach(raise, {
                onEnter(args) {
                    const sig = args[0].toInt32();
                    if (sig === 6 || sig === 11) { // SIGABRT, SIGSEGV
                        console.log("[!!!] Native raise(" + sig + ") — BLOCKED");
                        args[0] = ptr(0);
                        INTEL.exitPoints.usesNativeCrash = true;
                    }
                }
            });
            console.log("[+] Native raise() trap");
        }
    } catch(e) { console.log("[ ] Native raise() trap: " + e); }

    // 4f. Log DexClassLoader usage — dynamic code loading detection
    if (INTEL.obfuscation.hasDynamicLoad) {
        try {
            const DCL = Java.use("dalvik.system.DexClassLoader");
            DCL.$init.overload(
                'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
            ).implementation = function(dexPath, optimizedDir, libraryPath, parent) {
                log("DynLoad", "DexClassLoader loading: " + dexPath);
                return this.$init.overload(
                    'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
                ).call(this, dexPath, optimizedDir, libraryPath, parent);
            };
            console.log("[+] DexClassLoader monitor");
        } catch(e) { console.log("[ ] DexClassLoader monitor: " + e); }
    }

    // 4g. Signature check bypass
    try {
        const Signature = Java.use("android.content.pm.Signature");
        const APM = Java.use("android.app.ApplicationPackageManager");
        // Hook getPackageInfo to return unmodified signature (prevents checksum mismatch)
        // Most apps compare PackageInfo.signatures[0].toCharsString() to a hardcoded value
        // We can't easily spoof the actual cert — note this as needing static patch if triggered
        console.log("[i] Signature integrity: monitor only — static patch needed if triggered");
        INTEL.integrity.checksSignature = true;
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOGGING HELPER
// ═══════════════════════════════════════════════════════════════════════════════

function log(category, message) {
    if (!INTEL.logging.logDetectionEvents && category !== "SSL") return;
    if (category === "SSL" && !INTEL.logging.logSSLFailures) return;
    console.log("  [" + category + "] " + message);
}

function stackTraceHere(isLog) {
    try {
        Java.perform(function() {
            const Exception = Java.use('java.lang.Exception');
            const Log = Java.use('android.util.Log');
            const info = Log.getStackTraceString(Exception.$new());
            if (isLog) console.log(info);
            else return info;
        });
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN EXECUTION — Ordered phases
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n[*] Starting intelligence-first bypass engine...");
console.log("[*] Phase 0: Running recon...\n");

// Phase 0 — Native recon (synchronous, no Java.perform)
recon_NativeLibs();
recon_ProcMaps();
recon_TracerPid();

// Phase 2 native hooks run immediately (before Java.perform, as fopen fires early)
console.log("[*] Phase 2 (native): Attaching environment hooks...");
phase2_Environment();

// Phase 3 native SSL (libssl, libcrypto, Flutter)
console.log("[*] Phase 3 (native): Attaching native SSL hooks...");
phase3_NativeSSL();
phase3_FlutterSSL();

// Everything Java goes inside Java.perform
setTimeout(function() {
    Java.perform(function() {
        console.log("[*] Phase 0 (Java): Running Java class recon...");
        const loadedClasses = Java.enumerateLoadedClassesSync();
        recon_JavaClasses(loadedClasses);

        // Resolve strategy based on all collected intel
        resolveStrategy();

        // Print the full intelligence report
        printIntelReport();

        // Phase 1 — Anti-detection (must be first Java phase)
        console.log("[*] Phase 1: Anti-detection shield...");
        phase1_AntiDetection();

        // Phase 2 — Java environment spoofing
        console.log("[*] Phase 2 (Java): Environment spoofing...");
        phase2_JavaEnvironment();

        // Phase 3 — Java SSL bypass
        console.log("[*] Phase 3 (Java): SSL/TLS bypass...");
        phase3_JavaSSL();

        // Phase 4 — Stability
        console.log("[*] Phase 4: Stability hooks...");
        phase4_Stability();

        console.log("\n[*] All phases complete.");
        console.log("[*] Hook surface active: " + INTEL.strategy.hookSurface.join(", "));
        if (INTEL.strategy.needsFallback) {
            console.log("[!] FALLBACK WARNING: " + INTEL.strategy.fallbackReason);
        }
        console.log("[*] Ready — intercept traffic now.\n");
    });
}, 0);

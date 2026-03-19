/**
 * Frida SSL Unpinning + Root Detection Bypass Script
 * Updated: 2024 — Supports Android 7–14, Flutter, React Native,
 *          KernelSU, APatch, Zygisk, obfuscated OkHttp, API 33+ signatures
 *
 * Changes from original:
 *  - Flutter/BoringSSL native SSL bypass (libflutter.so)
 *  - Android 13+ PackageManager.getPackageInfo PackageInfoFlags overload
 *  - KernelSU + APatch package names added
 *  - Updated Magisk paths (v24+, Zygisk)
 *  - Deduplicated fopen hook (removed double-attach conflict)
 *  - Obfuscated OkHttp dynamic class scanner fallback
 *  - Native SSL: SSL_CTX_set_verify + X509_verify_cert hooks
 *  - ProcessImpl guard (only hook if class exists)
 *  - exec() family — now covers execve, execvp, execl via native hooks
 *  - bypassShellCheck wrapped in Java.perform with existence check
 */

// ─── UTILITY ────────────────────────────────────────────────────────────────

function stackTraceHere(isLog) {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new());
    if (isLog) {
        console.log(stackinfo);
    } else {
        return stackinfo;
    }
}

// ─── ROOT DETECTION DATA ─────────────────────────────────────────────────────

const commonPaths = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    // Magisk v24+ / Zygisk paths
    "/data/adb/magisk",
    "/data/adb/magisk/magisk",
    "/data/adb/magisk/magisk64",
    "/data/adb/magisk/magiskpolicy",
    "/data/adb/magisk.db",
    "/data/adb/magisk.img",
    "/data/adb/magisk_simple",
    "/data/adb/modules",
    "/data/adb/modules_update",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/init.magisk.rc",
    // Zygisk specific
    "/data/adb/magisk/zygisk",
    "/system/lib/zygisk.so",
    "/system/lib64/zygisk.so",
    // KernelSU
    "/data/adb/ksu",
    "/data/adb/ksud",
    "/data/adb/modules/.ksu",
    // APatch
    "/data/adb/ap",
    "/data/adb/apd",
    // Legacy
    "/system/xbin/ku.sud",
    "/system/xbin/magisk",
];

const ROOTmanagementApp = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "eu.chainfire.supersu.pro",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium",
    "com.formyhm.hideroot",
    "me.phh.superuser",
    "com.kingouser.com",
    "com.topjohnwu.magisk",
    // NEW: KernelSU
    "me.weishu.kernelsu",
    // NEW: APatch
    "com.bmax.raptor.superuser",
    // NEW: Magisk forks
    "io.github.huskydg.magisk",
    "com.github.androidadmin.kitsune",
];

const RootBinaries = [
    "su", "busybox", "supersu",
    "Superuser.apk", "KingoUser.apk", "SuperSu.apk",
    "magisk", "magisk64", "magiskpolicy", "magiskhide",
    "ksud", "ksu",   // KernelSU
    "apd",           // APatch
];

const RootProperties = {
    "ro.build.selinux": "1",
    "ro.debuggable": "0",
    "service.adb.root": "0",
    "ro.secure": "1"
};
const RootPropertiesKeys = Object.keys(RootProperties);

// ─── FLUTTER / BORINGSSL BYPASS ──────────────────────────────────────────────
// Flutter compiles BoringSSL into libflutter.so and never touches javax.net.ssl
// We must hook at the native level inside the .so itself.

function bypassFlutterSSL() {
    try {
        const flutter = Process.getModuleByName("libflutter.so");
        if (!flutter) {
            console.log("[ ] Flutter SSL bypass (libflutter.so not found)");
            return;
        }

        // Scan for ssl_verify_peer_cert — this is the BoringSSL callback
        // that Flutter registers. Signature: int ssl_verify_peer_cert(SSL *ssl)
        // We find it by pattern matching the function prologue.
        // Pattern works for arm64 Flutter stable builds (3.x)
        const pattern = "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9";
        Memory.scan(flutter.base, flutter.size, pattern, {
            onMatch(address) {
                console.log("  --> Flutter ssl_verify_peer_cert found at: " + address);
                Interceptor.attach(address, {
                    onLeave(retval) {
                        // SSL_VERIFY_OK = 0 in BoringSSL enum
                        retval.replace(ptr(0));
                        console.log("  --> Bypassing Flutter SSL verification");
                    }
                });
            },
            onError(reason) {
                console.log("  --> Flutter pattern scan error: " + reason);
            },
            onComplete() {}
        });

        // Also hook handshake_failure path used in newer Flutter versions
        try {
            const ssl_crypto_x509_session_verify_cert_chain = flutter.findExportByName(
                "ssl_crypto_x509_session_verify_cert_chain"
            );
            if (ssl_crypto_x509_session_verify_cert_chain) {
                Interceptor.attach(ssl_crypto_x509_session_verify_cert_chain, {
                    onLeave(retval) {
                        retval.replace(ptr(1)); // 1 = success in this path
                        console.log("  --> Bypassing Flutter ssl_crypto_x509_session_verify_cert_chain");
                    }
                });
                console.log("[+] Flutter ssl_crypto_x509_session_verify_cert_chain");
            }
        } catch (e) {}

        console.log("[+] Flutter SSL bypass (pattern scan initiated)");
    } catch (err) {
        console.log("[ ] Flutter SSL bypass: " + err);
    }
}

// ─── NATIVE SSL HOOKS (NDK apps, non-Java TLS) ──────────────────────────────

function bypassNativeSSL() {
    // Hook SSL_CTX_set_verify — replaces the app's custom verify callback with null (no verify)
    try {
        const libssl = Process.findModuleByName("libssl.so");
        if (libssl) {
            const SSL_CTX_set_verify = libssl.findExportByName("SSL_CTX_set_verify");
            if (SSL_CTX_set_verify) {
                Interceptor.attach(SSL_CTX_set_verify, {
                    onEnter(args) {
                        // args[1] = mode, args[2] = callback
                        // Set mode to SSL_VERIFY_NONE (0), null callback
                        args[1] = ptr(0);
                        args[2] = ptr(0);
                        console.log("  --> Bypassing SSL_CTX_set_verify (native)");
                    }
                });
                console.log("[+] SSL_CTX_set_verify (native libssl)");
            }
        } else {
            console.log("[ ] SSL_CTX_set_verify (libssl.so not loaded)");
        }
    } catch (err) {
        console.log("[ ] SSL_CTX_set_verify: " + err);
    }

    // Hook X509_verify_cert — direct certificate chain verification in BoringSSL/OpenSSL
    try {
        const libcrypto = Process.findModuleByName("libcrypto.so");
        if (libcrypto) {
            const X509_verify_cert = libcrypto.findExportByName("X509_verify_cert");
            if (X509_verify_cert) {
                Interceptor.attach(X509_verify_cert, {
                    onLeave(retval) {
                        if (retval.toInt32() !== 1) {
                            retval.replace(ptr(1)); // 1 = verified OK
                            console.log("  --> Bypassing X509_verify_cert (native)");
                        }
                    }
                });
                console.log("[+] X509_verify_cert (native libcrypto)");
            }
        } else {
            console.log("[ ] X509_verify_cert (libcrypto.so not loaded)");
        }
    } catch (err) {
        console.log("[ ] X509_verify_cert: " + err);
    }
}

// ─── NATIVE FILE / EXEC HOOKS ────────────────────────────────────────────────
// Single unified fopen hook — no duplicate attach conflict

function bypassNativeFileCheck() {
    // fopen — check path against root paths list
    const fopen = Module.findExportByName("libc.so", "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter(args) {
                this.inputPath = args[0].readUtf8String();
                // Redirect both known paths and anything containing "magisk"/"ksu"/"apd"
                const shouldBlock =
                    commonPaths.indexOf(this.inputPath) >= 0 ||
                    this.inputPath.indexOf("magisk") >= 0 ||
                    this.inputPath.indexOf("/ksu") >= 0 ||
                    this.inputPath.indexOf("/adb/ap") >= 0;
                if (shouldBlock) {
                    console.log("Anti Root Detect - fopen blocked: " + this.inputPath);
                    args[0].writeUtf8String("/notexists");
                }
            }
        });
        console.log("[+] Native fopen hook (unified)");
    }

    // access() — used by many root checks via File.exists() equivalent in native
    const access = Module.findExportByName("libc.so", "access");
    if (access) {
        Interceptor.attach(access, {
            onEnter(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave(retval) {
                const shouldBlock =
                    commonPaths.indexOf(this.inputPath) >= 0 ||
                    this.inputPath.indexOf("magisk") >= 0 ||
                    this.inputPath.indexOf("/ksu") >= 0 ||
                    this.inputPath.indexOf("/adb/ap") >= 0;
                if (retval.toInt32() === 0 && shouldBlock) {
                    console.log("Anti Root Detect - access blocked: " + this.inputPath);
                    retval.replace(ptr(-1));
                }
            }
        });
        console.log("[+] Native access hook");
    }

    // stat / stat64 — another common file existence check
    ["stat", "__xstat", "stat64", "__xstat64"].forEach(function(fn) {
        try {
            const statFn = Module.findExportByName("libc.so", fn);
            if (statFn) {
                Interceptor.attach(statFn, {
                    onEnter(args) {
                        // For __xstat the path is args[1], for stat it's args[0]
                        const pathIdx = fn.startsWith("__x") ? 1 : 0;
                        try {
                            this.inputPath = args[pathIdx].readUtf8String();
                        } catch(e) { this.inputPath = ""; }
                    },
                    onLeave(retval) {
                        const shouldBlock =
                            commonPaths.indexOf(this.inputPath) >= 0 ||
                            this.inputPath.indexOf("magisk") >= 0;
                        if (retval.toInt32() === 0 && shouldBlock) {
                            console.log("Anti Root Detect - " + fn + " blocked: " + this.inputPath);
                            retval.replace(ptr(-1));
                        }
                    }
                });
            }
        } catch(e) {}
    });
    console.log("[+] Native stat family hooks");

    // Native exec family — covers what the Java Runtime.exec hooks miss
    // execve is the syscall everything funnels into
    try {
        const execve = Module.findExportByName("libc.so", "execve");
        if (execve) {
            Interceptor.attach(execve, {
                onEnter(args) {
                    try {
                        const cmd = args[0].readUtf8String();
                        if (cmd && (cmd.indexOf("su") !== -1 ||
                            cmd.indexOf("getprop") !== -1 ||
                            cmd.indexOf("magisk") !== -1)) {
                            console.log("Anti Root Detect - execve blocked: " + cmd);
                            args[0].writeUtf8String("/system/bin/grep");
                        }
                    } catch(e) {}
                }
            });
            console.log("[+] Native execve hook");
        }
    } catch(e) {
        console.log("[ ] Native execve hook: " + e);
    }

    // system() call
    try {
        const system = Module.findExportByName("libc.so", "system");
        if (system) {
            Interceptor.attach(system, {
                onEnter(args) {
                    try {
                        const cmd = args[0].readUtf8String();
                        if (cmd.indexOf("getprop") !== -1 || cmd === "mount" ||
                            cmd.indexOf("build.prop") !== -1 || cmd === "id" ||
                            cmd === "su" || cmd.indexOf("magisk") !== -1) {
                            console.log("Anti Root Detect - system() blocked: " + cmd);
                            args[0].writeUtf8String("grep");
                        }
                    } catch(e) {}
                }
            });
            console.log("[+] Native system() hook");
        }
    } catch(e) {
        console.log("[ ] Native system() hook: " + e);
    }
}

// ─── JAVA FILE CHECK ─────────────────────────────────────────────────────────

function bypassJavaFileCheck() {
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
                console.log("Anti Root Detect - Java checkAccess blocked: " + filename);
                return false;
            }
            return this.checkAccess(file, access);
        };
        console.log("[+] Java UnixFileSystem.checkAccess hook");
    } catch(e) {
        console.log("[ ] Java UnixFileSystem.checkAccess: " + e);
    }
}

// ─── BUILD PROP / SYSTEM PROPERTIES ─────────────────────────────────────────

function setProp() {
    try {
        const Build = Java.use("android.os.Build");
        const fields = { "TAGS": "release-keys", "TYPE": "user" };
        for (const [field, value] of Object.entries(fields)) {
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
    } catch(e) {
        console.log("[ ] Build field spoof: " + e);
    }

    try {
        const system_property_get = Module.findExportByName("libc.so", "__system_property_get");
        if (system_property_get) {
            Interceptor.attach(system_property_get, {
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
                        "ro.build.selinux": "1"
                    };
                    if (this.key && fakeProps[this.key]) {
                        const val = fakeProps[this.key];
                        const p = Memory.allocUtf8String(val);
                        Memory.copy(this.ret, p, val.length + 1);
                    }
                }
            });
            console.log("[+] __system_property_get hook");
        }
    } catch(e) {
        console.log("[ ] __system_property_get: " + e);
    }
}

// ─── ROOT APP CHECK — Android 13+ aware ──────────────────────────────────────

function bypassRootAppCheck() {
    try {
        const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");

        // Original signature — Android < 13
        try {
            ApplicationPackageManager.getPackageInfo.overload(
                'java.lang.String', 'int'
            ).implementation = function(str, i) {
                if (ROOTmanagementApp.indexOf(str) >= 0) {
                    console.log("Anti Root Detect - getPackageInfo(int) blocked: " + str);
                    str = "not.found.fake.package";
                }
                return this.getPackageInfo(str, i);
            };
            console.log("[+] getPackageInfo(String, int) hook");
        } catch(e) {
            console.log("[ ] getPackageInfo(String, int): " + e);
        }

        // NEW: Android 13+ (API 33) uses PackageInfoFlags object overload
        try {
            const PackageInfoFlags = Java.use("android.content.pm.PackageManager$PackageInfoFlags");
            ApplicationPackageManager.getPackageInfo.overload(
                'java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags'
            ).implementation = function(str, flags) {
                if (ROOTmanagementApp.indexOf(str) >= 0) {
                    console.log("Anti Root Detect - getPackageInfo(Flags) blocked: " + str);
                    str = "not.found.fake.package";
                }
                return this.getPackageInfo(str, flags);
            };
            console.log("[+] getPackageInfo(String, PackageInfoFlags) hook — Android 13+");
        } catch(e) {
            console.log("[ ] getPackageInfo(String, PackageInfoFlags): " + e);
        }

        // getInstalledPackages also used by some root checkers
        try {
            ApplicationPackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
                const pkgList = this.getInstalledPackages(flags);
                const Iterator = Java.use("java.util.Iterator");
                const iter = pkgList.iterator();
                while (iter.hasNext()) {
                    const pkgInfo = iter.next();
                    const pname = pkgInfo.packageName.value;
                    if (ROOTmanagementApp.indexOf(pname) >= 0) {
                        console.log("Anti Root Detect - getInstalledPackages removed: " + pname);
                        iter.remove();
                    }
                }
                return pkgList;
            };
            console.log("[+] getInstalledPackages hook");
        } catch(e) {
            console.log("[ ] getInstalledPackages: " + e);
        }

    } catch(e) {
        console.log("[ ] bypassRootAppCheck: " + e);
    }
}

// ─── SHELL CHECK — with existence guard ──────────────────────────────────────

function bypassShellCheck() {
    // Guard: ProcessImpl may not exist on all Android versions
    const loaded = Java.enumerateLoadedClassesSync();
    const hasProcessImpl = loaded.indexOf('java.lang.ProcessImpl') !== -1;

    if (!hasProcessImpl) {
        console.log("[ ] ProcessImpl not loaded — skipping shell check bypass");
        return;
    }

    try {
        const Str = Java.use('java.lang.String');
        const ProcessImpl = Java.use("java.lang.ProcessImpl");
        ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
            const cmd0 = cmdarray[0] ? cmdarray[0] : "";
            const cmd1 = cmdarray.length > 1 ? cmdarray[1] : "";

            if (cmd0 === "mount" || cmd0 === "id") {
                console.log("Anti Root Detect - ProcessImpl blocked: " + cmdarray.toString());
                arguments[0] = Java.array('java.lang.String', [Str.$new("")]);
                return ProcessImpl.start.apply(this, arguments);
            }
            if (cmd0 === "getprop") {
                const blockedProps = ["ro.secure", "ro.debuggable", "ro.build.tags"];
                if (blockedProps.indexOf(cmd1) >= 0) {
                    console.log("Anti Root Detect - ProcessImpl getprop blocked: " + cmd1);
                    arguments[0] = Java.array('java.lang.String', [Str.$new("")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }
            if (cmd0.indexOf("which") >= 0 && cmd1 === "su") {
                console.log("Anti Root Detect - ProcessImpl which su blocked");
                arguments[0] = Java.array('java.lang.String', [Str.$new("")]);
                return ProcessImpl.start.apply(this, arguments);
            }
            if (cmd0 === "su" || (cmdarray.length > 0 && cmdarray.indexOf("su") >= 0)) {
                console.log("Anti Root Detect - ProcessImpl su blocked");
                arguments[0] = Java.array('java.lang.String', [Str.$new("justafakecommandthatdoesnotexist")]);
                return ProcessImpl.start.apply(this, arguments);
            }
            return ProcessImpl.start.apply(this, arguments);
        };
        console.log("[+] ProcessImpl.start hook");
    } catch(e) {
        console.log("[ ] ProcessImpl.start: " + e);
    }
}

// ─── /proc/self/maps ZYGISK DETECTION BYPASS ────────────────────────────────
// Apps reading /proc/self/maps to find injected Frida/Zygisk/Magisk libs

function bypassProcMapsCheck() {
    Java.perform(function() {
        try {
            const BufferedReader = Java.use("java.io.BufferedReader");
            BufferedReader.readLine.overload().implementation = function() {
                let line = this.readLine.overload().call(this);
                if (line !== null) {
                    // Strip lines revealing Frida, Magisk, or Zygisk presence
                    const suspicious = ["frida", "gadget", "magisk", "zygisk", "lsplant", "ksu"];
                    for (const keyword of suspicious) {
                        if (line.toLowerCase().indexOf(keyword) >= 0) {
                            console.log("Anti Detect - /proc/maps line hidden: " + line);
                            line = "";
                        }
                    }
                    // Original test-keys bypass
                    if (line.indexOf("ro.build.tags=test-keys") > -1) {
                        line = line.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                    }
                }
                return line;
            };
            console.log("[+] BufferedReader.readLine hook (maps + build.prop)");
        } catch(e) {
            console.log("[ ] BufferedReader.readLine: " + e);
        }
    });
}

// ─── OBFUSCATED OKHTTP DYNAMIC FALLBACK ─────────────────────────────────────
// If ProGuard renamed okhttp3.CertificatePinner, scan loaded classes for it

function bypassObfuscatedOkHttp() {
    try {
        const classes = Java.enumerateLoadedClassesSync();
        // Look for any class that has "CertificatePinner" in its name after obfuscation
        // Obfuscated names are short (1-3 chars) so we match on method signature instead
        classes.forEach(function(cls) {
            if (cls.indexOf("CertificatePinner") >= 0 && cls.indexOf("okhttp") < 0) {
                try {
                    const Cls = Java.use(cls);
                    if (Cls.check) {
                        Cls.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                            console.log("  --> Bypassing obfuscated CertificatePinner: " + cls);
                            return;
                        };
                        console.log("[+] Obfuscated CertificatePinner found: " + cls);
                    }
                } catch(e) {}
            }
        });
    } catch(e) {
        console.log("[ ] Obfuscated OkHttp scan: " + e);
    }
}

// ─── SSL UNPINNING (JAVA LAYER) ───────────────────────────────────────────────

setTimeout(function() {
    Java.perform(function() {
        console.log("---");
        console.log("Unpinning Android app...");

        // Generic SSLPeerUnverifiedException auto-patcher
        try {
            const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
            UnverifiedCertError.$init.implementation = function(str) {
                console.log('  --> Unexpected SSL verification failure, adding dynamic patch...');
                try {
                    const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(stack =>
                        stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();
                    console.log(`      Thrown by ${className}->${methodName}`);
                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];
                    if (callingMethod.implementation) return;
                    const returnTypeName = callingMethod.returnType.type;
                    callingMethod.implementation = function() {
                        console.log(`  --> Bypassing ${className}->${methodName} (auto patch)`);
                        return returnTypeName === 'void' ? undefined : null;
                    };
                    console.log(`      [+] ${className}->${methodName} (auto patch)`);
                } catch(e) {
                    console.log('      [ ] Failed to auto-patch: ' + e);
                }
                return this.$init(str);
            };
            console.log('[+] SSLPeerUnverifiedException auto-patcher');
        } catch(err) {
            console.log('[ ] SSLPeerUnverifiedException auto-patcher');
        }

        // HttpsURLConnection
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hv) {
                console.log('  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)');
            };
            console.log('[+] HttpsURLConnection (setDefaultHostnameVerifier)');
        } catch(err) { console.log('[ ] HttpsURLConnection (setDefaultHostnameVerifier)'); }

        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function(f) {
                console.log('  --> Bypassing HttpsURLConnection (setSSLSocketFactory)');
            };
            console.log('[+] HttpsURLConnection (setSSLSocketFactory)');
        } catch(err) { console.log('[ ] HttpsURLConnection (setSSLSocketFactory)'); }

        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setHostnameVerifier.implementation = function(hv) {
                console.log('  --> Bypassing HttpsURLConnection (setHostnameVerifier)');
            };
            console.log('[+] HttpsURLConnection (setHostnameVerifier)');
        } catch(err) { console.log('[ ] HttpsURLConnection (setHostnameVerifier)'); }

        // SSLContext
        try {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');
            const TrustManager = Java.registerClass({
                name: 'dev.asd.test.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            const TrustManagers = [TrustManager.$new()];
            const SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
            );
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log('  --> Bypassing Trustmanager (Android < 7)');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            console.log('[+] SSLContext');
        } catch(err) { console.log('[ ] SSLContext'); }

        // TrustManagerImpl (Android 7+)
        try {
            const array_list = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                console.log('  --> Bypassing TrustManagerImpl checkTrustedRecursive');
                return array_list.$new();
            };
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log('  --> Bypassing TrustManagerImpl verifyChain: ' + host);
                return untrustedChain;
            };
            console.log('[+] TrustManagerImpl');
        } catch(err) { console.log('[ ] TrustManagerImpl'); }

        // OkHTTPv3 (quadruple bypass)
        try {
            const cp1 = Java.use('okhttp3.CertificatePinner');
            cp1.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                console.log('  --> Bypassing OkHTTPv3 (list): ' + a);
            };
            console.log('[+] OkHTTPv3 (list)');
        } catch(err) { console.log('[ ] OkHTTPv3 (list)'); }

        try {
            const cp2 = Java.use('okhttp3.CertificatePinner');
            cp2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
                console.log('  --> Bypassing OkHTTPv3 (cert): ' + a);
            };
            console.log('[+] OkHTTPv3 (cert)');
        } catch(err) { console.log('[ ] OkHTTPv3 (cert)'); }

        try {
            const cp3 = Java.use('okhttp3.CertificatePinner');
            cp3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(a, b) {
                console.log('  --> Bypassing OkHTTPv3 (cert array): ' + a);
            };
            console.log('[+] OkHTTPv3 (cert array)');
        } catch(err) { console.log('[ ] OkHTTPv3 (cert array)'); }

        try {
            const cp4 = Java.use('okhttp3.CertificatePinner');
            cp4['check$okhttp'].implementation = function(a, b) {
                console.log('  --> Bypassing OkHTTPv3 ($okhttp): ' + a);
            };
            console.log('[+] OkHTTPv3 ($okhttp)');
        } catch(err) { console.log('[ ] OkHTTPv3 ($okhttp)'); }

        // NEW: Obfuscated OkHttp dynamic scan
        bypassObfuscatedOkHttp();

        // Trustkit
        try {
            const tk1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            tk1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
                console.log('  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): ' + a);
                return true;
            };
            console.log('[+] Trustkit OkHostnameVerifier(SSLSession)');
        } catch(err) { console.log('[ ] Trustkit OkHostnameVerifier(SSLSession)'); }

        try {
            const tk2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            tk2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
                console.log('  --> Bypassing Trustkit OkHostnameVerifier(cert): ' + a);
                return true;
            };
            console.log('[+] Trustkit OkHostnameVerifier(cert)');
        } catch(err) { console.log('[ ] Trustkit OkHostnameVerifier(cert)'); }

        try {
            const tk3 = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
            tk3.checkServerTrusted.implementation = function() {
                console.log('  --> Bypassing Trustkit PinningTrustManager');
            };
            console.log('[+] Trustkit PinningTrustManager');
        } catch(err) { console.log('[ ] Trustkit PinningTrustManager'); }

        // Appcelerator Titanium
        try {
            const appc = Java.use('appcelerator.https.PinningTrustManager');
            appc.checkServerTrusted.implementation = function() {
                console.log('  --> Bypassing Appcelerator PinningTrustManager');
            };
            console.log('[+] Appcelerator PinningTrustManager');
        } catch(err) { console.log('[ ] Appcelerator PinningTrustManager'); }

        // OpenSSLSocketImpl Conscrypt
        try {
            const OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, JavaObject, authMethod) {
                console.log('  --> Bypassing OpenSSLSocketImpl Conscrypt');
            };
            console.log('[+] OpenSSLSocketImpl Conscrypt');
        } catch(err) { console.log('[ ] OpenSSLSocketImpl Conscrypt'); }

        // OpenSSLEngineSocketImpl Conscrypt
        try {
            const OpenSSLEngineSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
            OpenSSLEngineSocketImpl.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(a, b) {
                console.log('  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
            };
            console.log('[+] OpenSSLEngineSocketImpl Conscrypt');
        } catch(err) { console.log('[ ] OpenSSLEngineSocketImpl Conscrypt'); }

        // OpenSSLSocketImpl Apache Harmony
        try {
            const OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function(a, b) {
                console.log('  --> Bypassing OpenSSLSocketImpl Apache Harmony');
            };
            console.log('[+] OpenSSLSocketImpl Apache Harmony');
        } catch(err) { console.log('[ ] OpenSSLSocketImpl Apache Harmony'); }

        // PhoneGap sslCertificateChecker
        try {
            const phonegap = Java.use('nl.xservices.plugins.sslCertificateChecker');
            phonegap.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
                console.log('  --> Bypassing PhoneGap sslCertificateChecker: ' + a);
                return true;
            };
            console.log('[+] PhoneGap sslCertificateChecker');
        } catch(err) { console.log('[ ] PhoneGap sslCertificateChecker'); }

        // IBM MobileFirst
        try {
            const WLClient1 = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function(cert) {
                console.log('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): ' + cert);
            };
            console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
        } catch(err) { console.log('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)'); }

        try {
            const WLClient2 = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function(cert) {
                console.log('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (array): ' + cert);
            };
            console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (array)');
        } catch(err) { console.log('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (array)'); }

        // IBM WorkLight HostNameVerifierWithCertificatePinning
        const wlBase = 'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning';
        [
            ['java.lang.String', 'javax.net.ssl.SSLSocket'],
            ['java.lang.String', 'java.security.cert.X509Certificate'],
            ['java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;'],
        ].forEach(function(sig) {
            try {
                const Cls = Java.use(wlBase);
                Cls.verify.overload(...sig).implementation = function() {
                    console.log('  --> Bypassing IBM WorkLight HostNameVerifier (' + sig[1] + ')');
                    return sig.length === 3 ? undefined : true;
                };
                console.log('[+] IBM WorkLight HostNameVerifier (' + sig[1] + ')');
            } catch(e) { console.log('[ ] IBM WorkLight HostNameVerifier (' + sig[1] + ')'); }
        });

        try {
            const wl4 = Java.use(wlBase);
            wl4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
                console.log('  --> Bypassing IBM WorkLight HostNameVerifier (SSLSession): ' + a);
                return true;
            };
            console.log('[+] IBM WorkLight HostNameVerifier (SSLSession)');
        } catch(e) { console.log('[ ] IBM WorkLight HostNameVerifier (SSLSession)'); }

        // Conscrypt CertPinManager
        try {
            const CertPinManager = Java.use('com.android.org.conscrypt.CertPinManager');
            CertPinManager.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                console.log('  --> Bypassing Conscrypt CertPinManager: ' + a);
                return true;
            };
            console.log('[+] Conscrypt CertPinManager');
        } catch(err) { console.log('[ ] Conscrypt CertPinManager'); }

        // CWAC-Netsecurity
        try {
            const cwac = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
            cwac.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                console.log('  --> Bypassing CWAC-Netsecurity CertPinManager: ' + a);
                return true;
            };
            console.log('[+] CWAC-Netsecurity CertPinManager');
        } catch(err) { console.log('[ ] CWAC-Netsecurity CertPinManager'); }

        // Worklight Androidgap WLCertificatePinningPlugin
        try {
            const wlgap = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
            wlgap.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
                console.log('  --> Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
                return true;
            };
            console.log('[+] Worklight Androidgap WLCertificatePinningPlugin');
        } catch(err) { console.log('[ ] Worklight Androidgap WLCertificatePinningPlugin'); }

        // Netty FingerprintTrustManagerFactory
        try {
            const netty = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
            netty.checkTrusted.implementation = function(type, chain) {
                console.log('  --> Bypassing Netty FingerprintTrustManagerFactory');
            };
            console.log('[+] Netty FingerprintTrustManagerFactory');
        } catch(err) { console.log('[ ] Netty FingerprintTrustManagerFactory'); }

        // Squareup CertificatePinner [OkHTTP < v3]
        try {
            const sq1 = Java.use('com.squareup.okhttp.CertificatePinner');
            sq1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
                console.log('  --> Bypassing Squareup CertificatePinner (cert): ' + a);
            };
            console.log('[+] Squareup CertificatePinner (cert)');
        } catch(err) { console.log('[ ] Squareup CertificatePinner (cert)'); }

        try {
            const sq2 = Java.use('com.squareup.okhttp.CertificatePinner');
            sq2.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
                console.log('  --> Bypassing Squareup CertificatePinner (list): ' + a);
            };
            console.log('[+] Squareup CertificatePinner (list)');
        } catch(err) { console.log('[ ] Squareup CertificatePinner (list)'); }

        // Squareup OkHostnameVerifier [OkHTTP v3]
        try {
            const sqh1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            sqh1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
                console.log('  --> Bypassing Squareup OkHostnameVerifier (cert): ' + a);
                return true;
            };
            console.log('[+] Squareup OkHostnameVerifier (cert)');
        } catch(err) { console.log('[ ] Squareup OkHostnameVerifier (cert)'); }

        try {
            const sqh2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            sqh2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
                console.log('  --> Bypassing Squareup OkHostnameVerifier (SSLSession): ' + a);
                return true;
            };
            console.log('[+] Squareup OkHostnameVerifier (SSLSession)');
        } catch(err) { console.log('[ ] Squareup OkHostnameVerifier (SSLSession)'); }

        // Android WebViewClient
        try {
            const wvc1 = Java.use('android.webkit.WebViewClient');
            wvc1.onReceivedSslError.overload(
                'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'
            ).implementation = function(obj1, obj2, obj3) {
                console.log('  --> Bypassing Android WebViewClient (SslErrorHandler)');
                obj2.proceed(); // Must call proceed() or the WebView hangs
            };
            console.log('[+] Android WebViewClient (SslErrorHandler)');
        } catch(err) { console.log('[ ] Android WebViewClient (SslErrorHandler)'); }

        try {
            const wvc2 = Java.use('android.webkit.WebViewClient');
            wvc2.onReceivedSslError.overload(
                'android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError'
            ).implementation = function(obj1, obj2, obj3) {
                console.log('  --> Bypassing Android WebViewClient (WebResourceError)');
            };
            console.log('[+] Android WebViewClient (WebResourceError)');
        } catch(err) { console.log('[ ] Android WebViewClient (WebResourceError)'); }

        // Apache Cordova WebViewClient
        try {
            const cordova = Java.use('org.apache.cordova.CordovaWebViewClient');
            cordova.onReceivedSslError.overload(
                'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'
            ).implementation = function(obj1, obj2, obj3) {
                console.log('  --> Bypassing Apache Cordova WebViewClient');
                obj2.proceed();
            };
            console.log('[+] Apache Cordova WebViewClient');
        } catch(err) { console.log('[ ] Apache Cordova WebViewClient'); }

        // Boye AbstractVerifier
        try {
            const boye = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
            boye.verify.implementation = function(host, ssl) {
                console.log('  --> Bypassing Boye AbstractVerifier: ' + host);
            };
            console.log('[+] Boye AbstractVerifier');
        } catch(err) { console.log('[ ] Boye AbstractVerifier'); }

        // Appmattus Certificate Transparency
        try {
            const appmattus = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor');
            appmattus['intercept'].implementation = function(a) {
                console.log('  --> Bypassing Appmattus (CertificateTransparencyInterceptor)');
                return a.proceed(a.request());
            };
            console.log('[+] Appmattus (CertificateTransparencyInterceptor)');
        } catch(err) { console.log('[ ] Appmattus (CertificateTransparencyInterceptor)'); }

        try {
            const CTtm = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager');
            CTtm['checkServerTrusted'].overload(
                '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
            ).implementation = function(x509, str) {
                console.log('  --> Bypassing Appmattus (CertificateTransparencyTrustManager) [2-arg]');
            };
            CTtm['checkServerTrusted'].overload(
                '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'
            ).implementation = function(x509, str, str2) {
                console.log('  --> Bypassing Appmattus (CertificateTransparencyTrustManager) [3-arg]');
                return Java.use('java.util.ArrayList').$new();
            };
            console.log('[+] Appmattus (CertificateTransparencyTrustManager)');
        } catch(err) { console.log('[ ] Appmattus (CertificateTransparencyTrustManager)'); }

        // Runtime.exec family (Java layer)
        try {
            const Runtime = Java.use('java.lang.Runtime');
            const suspectCmds = ["su", "getprop", "mount", "build.prop", "id", "sh", "magisk", "ksud"];
            function isSuspect(cmd) {
                return suspectCmds.some(s => cmd.indexOf(s) !== -1);
            }
            function fakeOrPass(cmd) {
                if (cmd === "su" || cmd.indexOf("magisk") !== -1) return "justafakecommand";
                return "grep";
            }
            ["overload('java.lang.String')",
             "overload('java.lang.String', '[Ljava.lang.String;')",
             "overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File')"
            ].forEach(function(sig) {
                try {
                    eval(`Runtime.exec.${sig}`).implementation = function(cmd) {
                        const c = typeof cmd === 'string' ? cmd : (cmd ? cmd.toString() : "");
                        if (isSuspect(c)) {
                            console.log("Anti Root Detect - Runtime.exec blocked: " + c);
                            return Runtime.exec.overload('java.lang.String').call(this, fakeOrPass(c));
                        }
                        return this.exec.apply(this, arguments);
                    };
                } catch(e) {}
            });
            console.log('[+] Runtime.exec family hooks');
        } catch(err) { console.log('[ ] Runtime.exec: ' + err); }

        // SystemProperties
        try {
            const SystemProperties = Java.use('android.os.SystemProperties');
            const get = SystemProperties.get.overload('java.lang.String');
            get.implementation = function(name) {
                if (RootPropertiesKeys.indexOf(name) !== -1) {
                    console.log("Anti Root Detect - SystemProperties.get blocked: " + name);
                    return RootProperties[name];
                }
                return this.get.call(this, name);
            };
            console.log('[+] SystemProperties.get hook');
        } catch(err) { console.log('[ ] SystemProperties.get'); }

        // String.contains test-keys
        try {
            const Str = Java.use('java.lang.String');
            Str.contains.implementation = function(name) {
                if (name === "test-keys") {
                    console.log("Anti Root Detect - test-keys check bypassed");
                    return false;
                }
                return this.contains.call(this, name);
            };
            console.log('[+] String.contains (test-keys) hook');
        } catch(err) { console.log('[ ] String.contains'); }

        // NativeFile.exists
        try {
            const NativeFile = Java.use('java.io.File');
            NativeFile.exists.implementation = function() {
                const name = NativeFile.getName.call(this);
                if (RootBinaries.indexOf(name) > -1) {
                    console.log("Anti Root Detect - File.exists() blocked: " + name);
                    return false;
                }
                return this.exists.call(this);
            };
            console.log('[+] File.exists hook');
        } catch(err) { console.log('[ ] File.exists'); }

        // ProcessBuilder
        try {
            const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
            ProcessBuilder.start.implementation = function() {
                const cmd = this.command.call(this);
                let shouldBlock = false;
                for (let i = 0; i < cmd.size(); i++) {
                    const c = cmd.get(i).toString();
                    if (c.indexOf("getprop") !== -1 || c.indexOf("mount") !== -1 ||
                        c.indexOf("build.prop") !== -1 || c === "id" ||
                        c === "su" || c.indexOf("magisk") !== -1) {
                        shouldBlock = true;
                        break;
                    }
                }
                if (shouldBlock) {
                    console.log("Anti Root Detect - ProcessBuilder blocked: " + cmd);
                    this.command.call(this, ["grep"]);
                    return this.start.call(this);
                }
                return this.start.call(this);
            };
            console.log('[+] ProcessBuilder.start hook');
        } catch(err) { console.log('[ ] ProcessBuilder.start'); }

        // Root app check
        bypassRootAppCheck();

        // /proc/self/maps + build.prop read bypass
        bypassProcMapsCheck();

        // Shell bypass (ProcessImpl — guarded)
        bypassShellCheck();

        console.log("Unpinning setup completed");
        console.log("---");
    });
}, 0);

// ─── NATIVE HOOKS (run immediately, outside Java.perform) ────────────────────
console.log("Attaching native hooks...");
bypassNativeFileCheck(); // unified fopen + access + stat + execve + system
bypassNativeSSL();       // SSL_CTX_set_verify + X509_verify_cert
bypassFlutterSSL();      // libflutter.so BoringSSL pattern scan
setProp();               // Build fields + __system_property_get
bypassJavaFileCheck();   // Wrapped in internal Java.perform inside function

console.log("Native hooks attached.");

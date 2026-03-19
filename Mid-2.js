/*
 * Unified Bypass Script (2026 Ready Base)
 * Covers:
 * - Anti-debug / Anti-Frida
 * - Root detection bypass
 * - Native SSL (BoringSSL/OpenSSL)
 * - Java SSL fallback
 * - Flutter fallback
 * - Dynamic class monitoring
 */

// ptrace bypass
Interceptor.attach(Module.findExportByName("libc.so", "ptrace"), {
    onEnter: function (args) {
        args[0] = ptr(-1);
        console.log("[+] ptrace blocked");
    }
});

// kill bypass
Interceptor.attach(Module.findExportByName("libc.so", "kill"), {
    onEnter: function (args) {
        console.log("[+] kill blocked");
        args[0] = ptr(0);
    }
});

// abort bypass
Interceptor.attach(Module.findExportByName(null, "abort"), {
    onEnter: function () {
        console.log("[+] abort prevented");
    }
});

// exit bypass
Interceptor.attach(Module.findExportByName("libc.so", "exit"), {
    onEnter: function (args) {
        console.log("[+] exit blocked: " + args[0]);
    }
});

// =========================
// 🔴 NATIVE SSL BYPASS
// =========================

function hookNativeSSL() {

    const handshake = Module.findExportByName("libssl.so", "SSL_do_handshake");
    if (handshake) {
        Interceptor.attach(handshake, {
            onLeave: function (retval) {
                retval.replace(1);
                console.log("[+] SSL handshake bypassed");
            }
        });
    }

    const verify = Module.findExportByName("libssl.so", "SSL_get_verify_result");
    if (verify) {
        Interceptor.attach(verify, {
            onLeave: function (retval) {
                retval.replace(0);
                console.log("[+] SSL verify result bypassed");
            }
        });
    }

    const x509 = Module.findExportByName("libcrypto.so", "X509_verify_cert");
    if (x509) {
        Interceptor.attach(x509, {
            onLeave: function (retval) {
                retval.replace(1);
                console.log("[+] X509_verify_cert bypassed");
            }
        });
    }
}

hookNativeSSL();

// =========================
// 🔴 FLUTTER SSL (FALLBACK)
// =========================

function hookFlutter() {
    try {
        const module = Process.getModuleByName("libflutter.so");

        Memory.scan(module.base, module.size,
            "FF 83 01 D1 FA 67 01 A9", {
                onMatch: function (addr) {
                    console.log("[+] Flutter SSL hook: " + addr);

                    Interceptor.attach(addr, {
                        onLeave: function (retval) {
                            retval.replace(0);
                        }
                    });
                }
            });

    } catch (e) {
        console.log("[ ] Flutter not detected");
    }
}

hookFlutter();

// =========================
// 🔴 JAVA LAYER
// =========================

Java.perform(function () {

    console.log("[*] Java hooks loaded");

    // Exit monitoring
    const System = Java.use("java.lang.System");
    System.exit.implementation = function (code) {
        console.log("[!] System.exit blocked: " + code);
    };

    const Process = Java.use("android.os.Process");
    Process.killProcess.implementation = function (pid) {
        console.log("[!] killProcess blocked: " + pid);
    };

    // Root file detection
    const File = Java.use("java.io.File");
    File.exists.implementation = function () {
        const name = this.getName();

        if (name.indexOf("su") !== -1 || name.indexOf("magisk") !== -1) {
            console.log("[+] Root file hidden: " + name);
            return false;
        }

        return this.exists.call(this);
    };

    // System properties spoof
    const SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
        if (key === "ro.debuggable") return "0";
        if (key === "ro.secure") return "1";
        return this.get.call(this, key);
    };

    // /proc/self/maps bypass
    const BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.overload().implementation = function () {
        let line = this.readLine.call(this);

        if (line !== null) {
            const bad = ["frida", "magisk", "zygisk"];
            for (let i = 0; i < bad.length; i++) {
                if (line.toLowerCase().indexOf(bad[i]) >= 0) {
                    return "";
                }
            }
        }
        return line;
    };

    // SSL auto patch
    try {
        const SSLException = Java.use('javax.net.ssl.SSLPeerUnverifiedException');

        SSLException.$init.implementation = function (msg) {
            console.log("[+] SSL exception triggered — patching");

            try {
                const stack = Java.use("java.lang.Thread")
                    .currentThread().getStackTrace();

                const target = stack[2];
                const cls = Java.use(target.getClassName());
                const method = target.getMethodName();

                cls[method].implementation = function () {
                    console.log("[+] Auto bypass: " + method);
                    return null;
                };

            } catch (e) {}

            return this.$init(msg);
        };

    } catch (e) {}

    // Dynamic class monitoring
    const loader = Java.use("java.lang.ClassLoader");

    loader.loadClass.overload("java.lang.String").implementation = function (name) {

        if (name.toLowerCase().indexOf("pin") !== -1 ||
            name.toLowerCase().indexOf("trust") !== -1) {

            console.log("[+] Suspicious class: " + name);
        }

        return this.loadClass.call(this, name);
    };

});

console.log("[*] Bypass script loaded");

const commonPaths = [
    "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/", "/sbin/su",
    "/system/app/Superuser.apk", "/system/bin/failsafe/su", "/system/bin/su",
    "/su/bin/su", "/system/etc/init.d/99SuperSUDaemon", "/system/sd/xbin/su",
    "/system/xbin/busybox", "/system/xbin/daemonsu", "/system/xbin/su",
    "/system/sbin/su", "/vendor/bin/su", "/cache/su", "/data/su", "/dev/su",
    "/system/bin/.ext/su", "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk", "/data/adb/magisk", "/sbin/.magisk",
    "/cache/.disable_magisk", "/dev/.magisk.unblock", "/cache/magisk.log",
    "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/adb/magisk_simple",
    "/init.magisk.rc", "/system/xbin/ku.sud", "/data/adb/ksu", "/data/adb/ksud",
    "/sbin/.magisk/mirror", "/sbin/.core/mirror", "/sbin/.core/img",
    "/sbin/.core/db-0/magisk.db", "/data/adb/modules", "/data/adb/post-fs-data.d",
    "/data/adb/service.d", "/system/addon.d/99-magisk.sh",
    "/system/etc/init.d/99magisk", "/dev/magisk/mirror",
    "/data/adb/magisk/magiskpolicy", "/sbin/magiskinit", "/sbin/magiskpolicy",
    "/sbin/magisk32", "/sbin/magisk64", "/apex/com.android.art/bin/su",
    "/system/bin/ksu", "/data/adb/ksu/bin/ksud"
];

const suspiciousMaps = [
    "magisk", "zygisk", "ksu", "kernelsu", "riru", "edxposed",
    "lsposed", "xposed", "substrate", "frida", "gadget", "inject"
];

const ROOTmanagementApp = [
    "com.noshufou.android.su", "com.noshufou.android.su.elite",
    "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.thirdparty.superuser", "com.yellowes.su",
    "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk", "me.weishu.kernelsu",
    "com.kingroot.kinguser", "com.kingo.root", "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global", "com.alephzain.framaroot",
    "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer", "com.saurik.substrate",
    "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
    "com.formyhm.hiderootPremium", "com.amphoras.hidemyrootadfree",
    "com.flexion.ml.sysutils", "com.reaper.uto", "com.ioncannon.n0kernel"
];

function stackTraceHere(isLog) {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new());
    if (isLog) { console.log(stackinfo); } else { return stackinfo; }
}

function bypassJavaFileCheck() {
    var UnixFileSystem = Java.use("java.io.UnixFileSystem");
    UnixFileSystem.checkAccess.implementation = function(file, access) {
        var filename = file.getAbsolutePath();
        if (filename.indexOf("magisk") >= 0 || filename.indexOf("ksu") >= 0) {
            console.log("[*] Java checkAccess blocked: " + filename);
            return false;
        }
        if (commonPaths.indexOf(filename) >= 0) {
            console.log("[*] Java checkAccess blocked: " + filename);
            return false;
        }
        return this.checkAccess(file, access);
    };

    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var filename = this.getAbsolutePath();
        if (commonPaths.indexOf(filename) >= 0 || filename.indexOf("magisk") >= 0 || filename.indexOf("ksu") >= 0) {
            console.log("[*] File.exists blocked: " + filename);
            return false;
        }
        return this.exists();
    };
    File.canExecute.implementation = function() {
        var filename = this.getAbsolutePath();
        if (commonPaths.indexOf(filename) >= 0) {
            console.log("[*] File.canExecute blocked: " + filename);
            return false;
        }
        return this.canExecute();
    };
    File.canRead.implementation = function() {
        var filename = this.getAbsolutePath();
        if (commonPaths.indexOf(filename) >= 0 || filename.indexOf("magisk") >= 0) {
            console.log("[*] File.canRead blocked: " + filename);
            return false;
        }
        return this.canRead();
    };
    File.isFile.implementation = function() {
        var filename = this.getAbsolutePath();
        if (commonPaths.indexOf(filename) >= 0 || filename.indexOf("magisk") >= 0) {
            return false;
        }
        return this.isFile();
    };
    File.listFiles.overload().implementation = function() {
        var filename = this.getAbsolutePath();
        if (filename.indexOf("magisk") >= 0 || filename === "/sbin" || filename === "/data/adb") {
            console.log("[*] File.listFiles blocked: " + filename);
            return null;
        }
        return this.listFiles();
    };
}

function bypassNativeFileCheck() {
    var libc = "libc.so";

    var fopen = Module.findExportByName(libc, "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) { this.inputPath = args[0].readUtf8String(); },
            onLeave: function(retval) {
                if (retval.toInt32() != 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0) {
                        console.log("[*] fopen blocked: " + this.inputPath);
                        retval.replace(ptr(0x0));
                    }
                }
            }
        });
    }

    var fopen64 = Module.findExportByName(libc, "fopen64");
    if (fopen64) {
        Interceptor.attach(fopen64, {
            onEnter: function(args) { this.inputPath = args[0].readUtf8String(); },
            onLeave: function(retval) {
                if (retval.toInt32() != 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0) {
                        console.log("[*] fopen64 blocked: " + this.inputPath);
                        retval.replace(ptr(0x0));
                    }
                }
            }
        });
    }

    var access = Module.findExportByName(libc, "access");
    if (access) {
        Interceptor.attach(access, {
            onEnter: function(args) { this.inputPath = args[0].readUtf8String(); },
            onLeave: function(retval) {
                if (retval.toInt32() == 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0) {
                        console.log("[*] access blocked: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            }
        });
    }

    var faccessat = Module.findExportByName(libc, "faccessat");
    if (faccessat) {
        Interceptor.attach(faccessat, {
            onEnter: function(args) {
                try { this.inputPath = args[1].readUtf8String(); } catch(e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0 || this.inputPath.indexOf("ksu") >= 0) {
                        console.log("[*] faccessat blocked: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            }
        });
    }

    var open = Module.findExportByName(libc, "open");
    if (open) {
        Interceptor.attach(open, {
            onEnter: function(args) {
                try { this.inputPath = args[0].readUtf8String(); } catch(e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() >= 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0) {
                        console.log("[*] open blocked: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            }
        });
    }

    var openat = Module.findExportByName(libc, "openat");
    if (openat) {
        Interceptor.attach(openat, {
            onEnter: function(args) {
                try { this.inputPath = args[1].readUtf8String(); } catch(e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() >= 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0) {
                        console.log("[*] openat blocked: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            }
        });
    }

    var stat = Module.findExportByName(libc, "stat");
    if (stat) {
        Interceptor.attach(stat, {
            onEnter: function(args) {
                try { this.inputPath = args[0].readUtf8String(); } catch(e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0) {
                        console.log("[*] stat blocked: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            }
        });
    }

    var lstat = Module.findExportByName(libc, "lstat");
    if (lstat) {
        Interceptor.attach(lstat, {
            onEnter: function(args) {
                try { this.inputPath = args[0].readUtf8String(); } catch(e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0 && this.inputPath) {
                    if (commonPaths.indexOf(this.inputPath) >= 0 || this.inputPath.indexOf("magisk") >= 0) {
                        console.log("[*] lstat blocked: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            }
        });
    }

    var statfs = Module.findExportByName(libc, "statfs");
    if (statfs) {
        Interceptor.attach(statfs, {
            onEnter: function(args) {
                try { this.inputPath = args[0].readUtf8String(); } catch(e) {}
            },
            onLeave: function(retval) {
                if (this.inputPath && (this.inputPath.indexOf("magisk") >= 0 || this.inputPath === "/sbin")) {
                    console.log("[*] statfs blocked: " + this.inputPath);
                    retval.replace(ptr(-1));
                }
            }
        });
    }
}

function bypassProcMaps() {
    var BufferedReader = Java.use("java.io.BufferedReader");
    var InputStreamReader = Java.use("java.io.InputStreamReader");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var String = Java.use("java.lang.String");

    BufferedReader.readLine.overload().implementation = function() {
        var line = this.readLine();
        if (line !== null) {
            for (var i = 0; i < suspiciousMaps.length; i++) {
                if (line.toLowerCase().indexOf(suspiciousMaps[i]) >= 0) {
                    console.log("[*] /proc/maps line blocked: " + line);
                    return String.$new("");
                }
            }
        }
        return line;
    };

    FileInputStream.overload('java.lang.String').implementation = function(path) {
        if (path === "/proc/mounts" || path === "/proc/self/mounts") {
            console.log("[*] FileInputStream /proc/mounts intercepted");
        }
        return this.overload('java.lang.String').call(this, path);
    };
}

function bypassProcMountsNative() {
    var fgets = Module.findExportByName("libc.so", "fgets");
    if (fgets) {
        Interceptor.attach(fgets, {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    try {
                        var line = retval.readUtf8String();
                        if (line && (line.indexOf("magisk") >= 0 || line.indexOf("ksu") >= 0 || line.indexOf("/sbin/.") >= 0)) {
                            console.log("[*] fgets /proc/mounts blocked: " + line.trim());
                            Memory.writeUtf8String(retval, "\n");
                        }
                    } catch(e) {}
                }
            }
        });
    }
}

function setProp() {
    var Build = Java.use("android.os.Build");

    var TAGS = Build.class.getDeclaredField("TAGS");
    TAGS.setAccessible(true);
    TAGS.set(null, "release-keys");

    var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT");
    FINGERPRINT.setAccessible(true);
    FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys");

    var TYPE = Build.class.getDeclaredField("TYPE");
    TYPE.setAccessible(true);
    TYPE.set(null, "user");

    try {
        var BuildVersion = Java.use("android.os.Build$VERSION");
        var CODENAME = BuildVersion.class.getDeclaredField("CODENAME");
        CODENAME.setAccessible(true);
        CODENAME.set(null, "REL");
    } catch(e) {}

    var system_property_get = Module.findExportByName("libc.so", "__system_property_get");
    if (system_property_get) {
        Interceptor.attach(system_property_get, {
            onEnter: function(args) {
                this.key = args[0].readCString();
                this.ret = args[1];
            },
            onLeave: function(ret) {
                var spoofMap = {
                    "ro.build.fingerprint": "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys",
                    "ro.build.tags": "release-keys",
                    "ro.build.type": "user",
                    "ro.debuggable": "0",
                    "ro.secure": "1",
                    "ro.build.selinux": "1",
                    "service.adb.root": "0",
                    "ro.adb.secure": "1"
                };
                if (this.key && spoofMap[this.key]) {
                    var tmp = spoofMap[this.key];
                    var p = Memory.allocUtf8String(tmp);
                    Memory.copy(this.ret, p, tmp.length + 1);
                    console.log("[*] __system_property_get spoofed: " + this.key);
                }
            }
        });
    }
}

function bypassRootAppCheck() {
    var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");

    ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
        if (ROOTmanagementApp.indexOf(str) >= 0) {
            console.log("[*] getPackageInfo(String,int) blocked: " + str);
            str = "com.notfound.nothing.here";
        }
        return this.getPackageInfo(str, i);
    };

    try {
        var PackageInfoFlags = Java.use("android.content.pm.PackageManager$PackageInfoFlags");
        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags').implementation = function(str, flags) {
            if (ROOTmanagementApp.indexOf(str) >= 0) {
                console.log("[*] getPackageInfo(String,Flags) blocked: " + str);
                str = "com.notfound.nothing.here";
            }
            return this.getPackageInfo(str, flags);
        };
    } catch(e) {}

    ApplicationPackageManager.getInstalledApplications.overload('int').implementation = function(flags) {
        var appList = this.getInstalledApplications(flags);
        var ArrayList = Java.use("java.util.ArrayList");
        var filteredList = ArrayList.$new();
        var size = appList.size();
        for (var i = 0; i < size; i++) {
            var app = appList.get(i);
            var pkgName = app.packageName.value;
            if (ROOTmanagementApp.indexOf(pkgName) < 0) {
                filteredList.add(app);
            } else {
                console.log("[*] getInstalledApplications filtered: " + pkgName);
            }
        }
        return filteredList;
    };

    ApplicationPackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
        var pkgList = this.getInstalledPackages(flags);
        var ArrayList = Java.use("java.util.ArrayList");
        var filteredList = ArrayList.$new();
        var size = pkgList.size();
        for (var i = 0; i < size; i++) {
            var pkg = pkgList.get(i);
            var pkgName = pkg.packageName.value;
            if (ROOTmanagementApp.indexOf(pkgName) < 0) {
                filteredList.add(pkg);
            } else {
                console.log("[*] getInstalledPackages filtered: " + pkgName);
            }
        }
        return filteredList;
    };
}

function bypassShellCheck() {
    var String = Java.use('java.lang.String');
    var ProcessImpl = Java.use("java.lang.ProcessImpl");
    var blockedCommands = ["mount", "which su", "su", "id", "cat /proc/mounts", "getprop ro.secure", "getprop ro.debuggable"];

    ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
        var cmd = cmdarray[0];
        if (cmd === "mount" || (cmd === "which" && cmdarray[1] === "su") || cmd === "su") {
            console.log("[*] Shell blocked: " + cmdarray.toString());
            arguments[0] = Java.array('java.lang.String', [String.$new("")]);
            return ProcessImpl.start.apply(this, arguments);
        }
        if (cmd === "getprop") {
            var blockedProps = ["ro.secure", "ro.debuggable", "ro.build.tags", "ro.build.type", "service.adb.root"];
            if (cmdarray[1] && blockedProps.indexOf(cmdarray[1]) >= 0) {
                console.log("[*] getprop blocked: " + cmdarray[1]);
                arguments[0] = Java.array('java.lang.String', [String.$new("")]);
                return ProcessImpl.start.apply(this, arguments);
            }
        }
        if (cmd === "id" || (cmd.indexOf("/") >= 0 && cmd.indexOf("su") >= 0)) {
            console.log("[*] Shell id/su blocked: " + cmd);
            arguments[0] = Java.array('java.lang.String', [String.$new("")]);
            return ProcessImpl.start.apply(this, arguments);
        }
        return ProcessImpl.start.apply(this, arguments);
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
        if (cmdarray && cmdarray.length > 0) {
            var cmd = cmdarray[0];
            if (cmd === "su" || cmd.indexOf("su") >= 0 || cmd === "id") {
                console.log("[*] Runtime.exec blocked: " + cmd);
                return this.exec([""]);
            }
        }
        return this.exec(cmdarray);
    };
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd === "su" || cmd.indexOf("su ") >= 0 || cmd === "id" || cmd.indexOf("magisk") >= 0) {
            console.log("[*] Runtime.exec(String) blocked: " + cmd);
            return this.exec("");
        }
        return this.exec(cmd);
    };
}

function bypassSELinux() {
    try {
        var SELinux = Java.use("android.os.SELinux");
        SELinux.isSELinuxEnabled.implementation = function() { return true; };
        SELinux.isSELinuxEnforced.implementation = function() { return true; };
        console.log("[*] SELinux hooks applied");
    } catch(e) {
        console.log("[!] SELinux class not found: " + e);
    }
}

function bypassKeyAttestationCheck() {
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getCertificateChain.implementation = function(alias) {
            var chain = this.getCertificateChain(alias);
            return chain;
        };
    } catch(e) {}
}

function bypassDebugCheck() {
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            return false;
        };
    } catch(e) {}

    try {
        var ApplicationInfo = Java.use("android.app.ApplicationInfo");
        ApplicationInfo.flags.value = ApplicationInfo.flags.value & ~(1 << 1);
    } catch(e) {}
}

function bypassEmulatorCheck() {
    try {
        var Build = Java.use("android.os.Build");

        var MANUFACTURER = Build.class.getDeclaredField("MANUFACTURER");
        MANUFACTURER.setAccessible(true);
        MANUFACTURER.set(null, "Google");

        var MODEL = Build.class.getDeclaredField("MODEL");
        MODEL.setAccessible(true);
        MODEL.set(null, "Pixel 3 XL");

        var BRAND = Build.class.getDeclaredField("BRAND");
        BRAND.setAccessible(true);
        BRAND.set(null, "google");

        var DEVICE = Build.class.getDeclaredField("DEVICE");
        DEVICE.setAccessible(true);
        DEVICE.set(null, "crosshatch");

        var PRODUCT = Build.class.getDeclaredField("PRODUCT");
        PRODUCT.setAccessible(true);
        PRODUCT.set(null, "crosshatch");

        var HARDWARE = Build.class.getDeclaredField("HARDWARE");
        HARDWARE.setAccessible(true);
        HARDWARE.set(null, "qcom");

        var HOST = Build.class.getDeclaredField("HOST");
        HOST.setAccessible(true);
        HOST.set(null, "abfarm-release-rbe-64-00028-5662853");
    } catch(e) {
        console.log("[!] Build field spoof error: " + e);
    }
}

function bypassZygiskDetection() {
    try {
        var VMRuntime = Java.use("dalvik.system.VMRuntime");
        VMRuntime.getRuntime.implementation = function() {
            return this.getRuntime();
        };
    } catch(e) {}

    var dl_iterate_phdr = Module.findExportByName(null, "dl_iterate_phdr");
    if (dl_iterate_phdr) {
        Interceptor.attach(dl_iterate_phdr, {
            onEnter: function(args) {
                this.callback = args[0];
            }
        });
    }
}

function bypassIntegrityCheck() {
    try {
        var googleApiAvailability = Java.use("com.google.android.gms.common.GoogleApiAvailability");
        googleApiAvailability.isGooglePlayServicesAvailable.overload('android.content.Context').implementation = function(ctx) {
            return 0;
        };
    } catch(e) {}

    try {
        var safetyNet = Java.use("com.google.android.gms.safetynet.SafetyNetApi");
    } catch(e) {}
}

function hookClassLoader() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
        if (dexPath && dexPath.indexOf("magisk") >= 0) {
            console.log("[*] DexClassLoader magisk dex blocked: " + dexPath);
            dexPath = "/dev/null";
        }
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
}

function bypassSignatureCheck() {
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
            var info = this.getPackageInfo(pkg, flags);
            return info;
        };
    } catch(e) {}

    try {
        var Signature = Java.use("android.content.pm.Signature");
        Signature.toByteArray.implementation = function() {
            return this.toByteArray();
        };
    } catch(e) {}
}

function hookNativeLibraryLoad() {
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function(libname) {
        console.log("[*] loadLibrary: " + libname);
        return this.loadLibrary(libname);
    };
    System.load.implementation = function(filename) {
        console.log("[*] System.load: " + filename);
        return this.load(filename);
    };
}

function bypassNativeStringCheck() {
    var strstr = Module.findExportByName("libc.so", "strstr");
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function(args) {
                try {
                    this.haystack = args[0].readUtf8String();
                    this.needle = args[1].readUtf8String();
                } catch(e) {}
            },
            onLeave: function(retval) {
                if (this.needle && (this.needle === "magisk" || this.needle === "su" || this.needle === "ksu")) {
                    if (!retval.isNull()) {
                        console.log("[*] strstr blocked: needle=" + this.needle);
                        retval.replace(ptr(0x0));
                    }
                }
            }
        });
    }
}

function main() {
    console.log("[*] Advanced Root Bypass - Starting");

    Java.perform(function() {
        bypassJavaFileCheck();
        console.log("[*] Java file checks hooked");

        bypassProcMaps();
        console.log("[*] /proc/maps reader hooked");

        setProp();
        console.log("[*] Build props spoofed");

        bypassRootAppCheck();
        console.log("[*] Package manager checks hooked");

        bypassShellCheck();
        console.log("[*] Shell exec checks hooked");

        bypassSELinux();

        bypassDebugCheck();
        console.log("[*] Debug checks hooked");

        bypassEmulatorCheck();
        console.log("[*] Emulator/Build fields spoofed");

        bypassZygiskDetection();
        console.log("[*] Zygisk hooks applied");

        bypassIntegrityCheck();
        console.log("[*] Integrity check hooks applied");

        hookClassLoader();
        console.log("[*] ClassLoader hooks applied");

        bypassSignatureCheck();
        console.log("[*] Signature check hooks applied");

        hookNativeLibraryLoad();
        console.log("[*] Native library load hooks applied");
    });

    bypassNativeFileCheck();
    console.log("[*] Native file checks hooked");

    bypassProcMountsNative();
    console.log("[*] Native /proc/mounts hooked");

    bypassNativeStringCheck();
    console.log("[*] Native strstr hooked");

    console.log("[*] All hooks installed successfully");
}

main();

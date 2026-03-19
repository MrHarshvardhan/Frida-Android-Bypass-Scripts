Java.perform(function () {

    // Block self-kill
    var System = Java.use("java.lang.System");
    System.exit.implementation = function (code) {
        console.log("[+] System.exit blocked:", code);
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exit.implementation = function (code) {
        console.log("[+] Runtime.exit blocked:", code);
    };

    Runtime.halt.implementation = function (code) {
        console.log("[+] Runtime.halt blocked:", code);
    };

    // Debug checks
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        return false;
    };

    Debug.waitingForDebugger.implementation = function () {
        return false;
    };

    // Common root check lib
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () {
            return false;
        };
    } catch(e) {}

});

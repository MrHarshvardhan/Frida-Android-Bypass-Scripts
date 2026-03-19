Java.perform(function () {

    console.log("[*] Developer/ADB detection bypass loaded");

    var Secure = Java.use("android.provider.Settings$Secure");
    var Global = Java.use("android.provider.Settings$Global");

    function bypass(name) {
        if (name === "adb_enabled" || name === "development_settings_enabled") {
            console.log("[+] Bypass setting:", name);
            return true;
        }
        return false;
    }

    Secure.getInt.overload('android.content.ContentResolver','java.lang.String').implementation = function(resolver,name){
        if(bypass(name)) return 0;
        return this.getInt(resolver,name);
    };

    Secure.getInt.overload('android.content.ContentResolver','java.lang.String','int').implementation = function(resolver,name,def){
        if(bypass(name)) return 0;
        return this.getInt(resolver,name,def);
    };

    Global.getInt.overload('android.content.ContentResolver','java.lang.String').implementation = function(resolver,name){
        if(bypass(name)) return 0;
        return this.getInt(resolver,name);
    };

    Global.getInt.overload('android.content.ContentResolver','java.lang.String','int').implementation = function(resolver,name,def){
        if(bypass(name)) return 0;
        return this.getInt(resolver,name,def);
    };

});

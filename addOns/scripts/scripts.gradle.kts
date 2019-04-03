import org.zaproxy.gradle.addon.AddOnStatus

version = "25"
description = "Supports all JSR 223 scripting languages"

zapAddOn {
    addOnName.set("Script Console")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/zaproxy/zaproxy/wiki/ScriptConsole")
    }
}

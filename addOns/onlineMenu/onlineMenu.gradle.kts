import org.zaproxy.gradle.addon.AddOnStatus

version = "7"
description = "ZAP Online menu items"

zapAddOn {
    addOnName.set("Online menus")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsOnlineMenuOnlineMenu")
    }
}

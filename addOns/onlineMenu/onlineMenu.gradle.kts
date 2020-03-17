import org.zaproxy.gradle.addon.AddOnStatus

version = "8"
description = "ZAP Online menu items"

zapAddOn {
    addOnName.set("Online menus")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/online-menu/")
    }
}

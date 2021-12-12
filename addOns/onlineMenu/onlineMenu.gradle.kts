import org.zaproxy.gradle.addon.AddOnStatus

description = "ZAP Online menu items"

zapAddOn {
    addOnName.set("Online menus")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/online-menu/")
    }
}

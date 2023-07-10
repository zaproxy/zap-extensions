import org.zaproxy.gradle.addon.AddOnStatus

description = "ZAP Online menu items"

zapAddOn {
    addOnName.set("Online menus")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/online-menu/")
    }
}

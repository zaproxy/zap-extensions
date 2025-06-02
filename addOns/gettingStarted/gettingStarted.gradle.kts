import org.zaproxy.gradle.addon.AddOnStatus

description = "A short Getting Started with ZAP Guide"

zapAddOn {
    addOnName.set("Getting Started with ZAP Guide")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/getting-started-guide/")
    }
}

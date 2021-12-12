import org.zaproxy.gradle.addon.AddOnStatus

description = "A short Getting Started with ZAP Guide"

zapAddOn {
    addOnName.set("Getting Started with ZAP Guide")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/getting-started-guide/")
    }
}

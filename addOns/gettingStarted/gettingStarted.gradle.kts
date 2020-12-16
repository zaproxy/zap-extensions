import org.zaproxy.gradle.addon.AddOnStatus

version = "13"
description = "A short Getting Started with ZAP Guide"

zapAddOn {
    addOnName.set("Getting Started with ZAP Guide")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/getting-started-guide/")
        notBeforeVersion.set("2.10.0")
    }
}

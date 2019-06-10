import org.zaproxy.gradle.addon.AddOnStatus

version = "11"
description = "A short Getting Started with ZAP Guide"

zapAddOn {
    addOnName.set("Getting Started with ZAP Guide")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
        notBeforeVersion.set("2.8.0")
    }
}

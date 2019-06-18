import org.zaproxy.gradle.addon.AddOnStatus

version = "7"
description = "Display ZAP Tips and Tricks"

zapAddOn {
    addOnName.set("Tips and Tricks")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

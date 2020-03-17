import org.zaproxy.gradle.addon.AddOnStatus

version = "8"
description = "Display ZAP Tips and Tricks"

zapAddOn {
    addOnName.set("Tips and Tricks")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/tips-and-tricks/")
    }
}

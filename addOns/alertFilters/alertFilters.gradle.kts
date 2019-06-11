import org.zaproxy.gradle.addon.AddOnStatus

version = "9"
description = "Allows you to automate the changing of alert risk levels."

zapAddOn {
    addOnName.set("Context Alert Filters")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

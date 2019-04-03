import org.zaproxy.gradle.addon.AddOnStatus

version = "6"
description = "Adds an option to import a file of URLs. The file must be plain text with one URL per line."

zapAddOn {
    addOnName.set("Import files containing URLs")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

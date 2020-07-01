import org.zaproxy.gradle.addon.AddOnStatus

version = "1.0.0"
description = "Allows to import HAR archives into ZAP"

zapAddOn {
    addOnName.set("Import HAR archives")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/import-har-archive/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

version = "0.1.0"
description = "Allows to import/export HAR archives into ZAP"

zapAddOn {
    addOnName.set("Import/Export HAR archives")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

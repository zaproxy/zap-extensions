import org.zaproxy.gradle.addon.AddOnStatus

version = "24"
description = "The release quality Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.7")
}

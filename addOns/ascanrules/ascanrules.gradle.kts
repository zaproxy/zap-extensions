import org.zaproxy.gradle.addon.AddOnStatus

version = "33"
description = "The release quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

import org.zaproxy.gradle.addon.AddOnStatus

version = "25"
description = "The beta quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.5")
}

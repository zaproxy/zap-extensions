import org.zaproxy.gradle.addon.AddOnStatus

version = "7"
description = "Content Security Policy (CSP) Scanner"

zapAddOn {
    addOnName.set("Content Security Policy Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.shapesecurity:salvation:2.5.0")

    testImplementation(project(":testutils"))
}

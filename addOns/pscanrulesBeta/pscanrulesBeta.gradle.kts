import org.zaproxy.gradle.addon.AddOnStatus

version = "22"
description = "The beta quality Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.google.re2j:re2j:1.2")

    testImplementation(project(":testutils"))
}

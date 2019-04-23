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
    implementation("org.bitbucket.mstrobel:procyon-compilertools:0.5.25")

    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.9")
}

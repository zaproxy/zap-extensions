import org.zaproxy.gradle.addon.AddOnStatus

version = "25"
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
    implementation("com.shapesecurity:salvation:2.7.0")

    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.7")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf(
        "**/TestInfoPrivateAddressDisclosure.java",
        "**/TestInfoSessionIdURL.java"))
}

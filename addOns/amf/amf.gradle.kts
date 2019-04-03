version = "3"
description = "Adds support for AMF messages"

repositories {
    maven("https://repo.spring.io/ext-release-local/")
}

zapAddOn {
    addOnName.set("AMF")
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

val blazedsVersion = "4.0.0.14931"

dependencies {
    implementation("com.adobe.blazeds:blazeds-common:$blazedsVersion")
    implementation("com.adobe.blazeds:blazeds-core:$blazedsVersion")
}

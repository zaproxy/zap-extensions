version = "1.0.0"
description = "An add-on for automated authentication configuration, guided authentication configuration and authentication status scanning"

zapAddOn {
    addOnName.set("Authentication Helper")
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}
description = "Authentication Helper"

zapAddOn {
    addOnName.set("Authentication Helper")
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/authentication-helper/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

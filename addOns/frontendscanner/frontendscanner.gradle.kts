version = "1"
description = "Scan modern web applications relying heavily on Javascript."

zapAddOn {
    addOnName.set("Front-end Scanner")
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/front-end-scanner/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

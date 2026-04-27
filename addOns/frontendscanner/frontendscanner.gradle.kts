description = "Scan modern web applications relying heavily on Javascript."

zapAddOn {
    addOnName.set("Front-end Scanner")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/front-end-scanner/")
    }
}

spotless {
    format("js") {
        targetExclude("**/zapHomeFiles/frontendscanner/**/*.js")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

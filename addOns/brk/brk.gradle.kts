description = "Allows you to add breakpoints"

zapAddOn {
    addOnName.set("brk")
    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/brk/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

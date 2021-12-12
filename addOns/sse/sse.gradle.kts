description = "Allows you to view Server-Sent Events (SSE) communication."

zapAddOn {
    addOnName.set("Server-Sent Events")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/server-sent-events/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

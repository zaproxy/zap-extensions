description = "Analyzes HTTP headers using an LLM to detect security weaknesses."

zapAddOn {
    addOnName.set("LLM Header Analyzer")
    zapVersion.set("2.15.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

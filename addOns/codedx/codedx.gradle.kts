description = "Includes request and response data in XML reports and provides the ability to upload reports directly to a Code Dx server"

zapAddOn {
    addOnName.set("Code Dx Extension")
    zapVersion.set("2.11.1")

    manifest {
        author.set("Code Dx, Inc.")
        url.set("https://www.zaproxy.org/docs/desktop/addons/code-dx/")
    }
}

dependencies {
    implementation("org.apache.httpcomponents:httpmime:4.5.13")
    implementation("com.googlecode.json-simple:json-simple:1.1.1") {
        // Not needed.
        exclude(group = "junit")
    }
}

spotless {
    java {
        // Don't check license nor format/style, 3rd-party add-on.
        clearSteps()
    }
}

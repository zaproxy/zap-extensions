version = "3"
description = "Fingerprint web applications"

zapAddOn {
    addOnName.set("WAFP Extension")
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.googlecode.json-simple:json-simple:1.1.1")
    implementation("org.jdom:jdom:1.1.3")
    implementation("org.jsoup:jsoup:1.7.2")

    testImplementation(project(":testutils"))
}

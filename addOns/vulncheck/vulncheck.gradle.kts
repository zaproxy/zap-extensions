version = "2"
description = "list vulnerabilities from known databases"

zapAddOn {
    addOnName.set("VulnCheck Extension")
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.googlecode.json-simple:json-simple:1.1.1")
    implementation("org.jsoup:jsoup:1.7.2")
}

version = "13"
description = "Technology detection using Wappalyzer: wappalyzer.com"

zapAddOn {
    addOnName.set("Wappalyzer - Technology Detection")
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.google.re2j:re2j:1.2")

    testImplementation(project(":testutils"))
}

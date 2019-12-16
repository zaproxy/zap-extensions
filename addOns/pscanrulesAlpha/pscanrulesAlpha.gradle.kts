version = "27"
description = "The alpha quality Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules (alpha)")
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

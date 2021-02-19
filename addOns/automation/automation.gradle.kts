version = "0.0.1"
description = "Automation Framework."

zapAddOn {
    addOnName.set("Automation Framework")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.12.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.0")
    implementation("org.snakeyaml:snakeyaml-engine:2.2.1")
    testImplementation(project(":testutils"))
}

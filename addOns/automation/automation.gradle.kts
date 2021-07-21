description = "Automation Framework."

zapAddOn {
    addOnName.set("Automation Framework")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/automation-framework/")
    }
}

dependencies {
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jdk8:2.9.6")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.12.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.0")
    implementation("org.snakeyaml:snakeyaml-engine:2.2.1")
    testImplementation(project(":testutils"))
}

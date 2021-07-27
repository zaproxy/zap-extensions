description = "Automation Framework."

zapAddOn {
    addOnName.set("Automation Framework")
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/automation-framework/")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.12.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.0")
    implementation("org.snakeyaml:snakeyaml-engine:2.2.1")
    testImplementation(project(":testutils"))
}

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
    api("com.fasterxml.jackson.datatype:jackson-datatype-jdk8:2.9.6")
    api("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.12.0")
    api("com.fasterxml.jackson.core:jackson-databind:2.12.0")
    api("org.snakeyaml:snakeyaml-engine:2.2.1")
    testImplementation(project(":testutils"))
}

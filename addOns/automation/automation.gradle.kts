import org.zaproxy.gradle.addon.AddOnStatus

description = "Automation Framework."

zapAddOn {
    addOnName.set("Automation Framework")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/automation-framework/")
    }

    apiClientGen {
        api.set("org.zaproxy.addon.automation.AutomationAPI")
        messages.set(file("src/main/resources/org/zaproxy/addon/automation/resources/Messages.properties"))
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
    api("com.fasterxml.jackson.datatype:jackson-datatype-jdk8:2.13.0")
    api("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.13.0")
    api("com.fasterxml.jackson.core:jackson-databind:2.13.0")
    api("org.snakeyaml:snakeyaml-engine:2.3")
    testImplementation(project(":testutils"))
}

description = "Imports and spiders Postman definitions."

zapAddOn {
    addOnName.set("Postman Support")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/postman-support/")
    }

    apiClientGen {
        api.set("org.zaproxy.addon.postman.PostmanApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/postman/resources/Messages.properties"))
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
    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.5")

    testImplementation(project(":testutils"))
}

description = "A simple extension example."

zapAddOn {
    addOnName.set("Simple Example")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

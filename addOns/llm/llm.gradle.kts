description = "An add-on to leverage LLM within ZAP."

zapAddOn {
    addOnName.set("LLM Support")

    manifest {
        author.set("Abdessamad TEMMAR")
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
    implementation("dev.langchain4j:langchain4j:0.35.0")
    implementation("dev.langchain4j:langchain4j-azure-open-ai:0.35.0")
    implementation("dev.langchain4j:langchain4j-ollama:0.35.0")

    testImplementation(project(":testutils"))
}

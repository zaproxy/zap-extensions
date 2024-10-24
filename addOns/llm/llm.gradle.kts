description = "An extension to leverage LLM within ZAP."

zapAddOn {
    addOnName.set("LLM Extension")

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

    zapAddOn("automation")
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
    implementation("dev.langchain4j:langchain4j:0.35.0")
    implementation("dev.langchain4j:langchain4j-azure-open-ai:0.35.0")

}


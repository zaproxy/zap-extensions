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
    implementation(libs.llm.langchain4j)
    implementation(libs.llm.langchain4j.azureOpenAi)
    implementation(libs.llm.langchain4j.ollama)

    testImplementation(project(":testutils"))
}

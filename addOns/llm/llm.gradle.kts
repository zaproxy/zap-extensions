description = "An add-on to leverage LLM within ZAP."

zapAddOn {
    addOnName.set("LLM Support")

    manifest {
        author.set("Abdessamad TEMMAR and the ZAP Core Team")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.39.0")
                }
            }
        }
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
    zapAddOn("commonlib")

    api(libs.llm.langchain4j)
    implementation(libs.llm.langchain4j.azureOpenAi)
    implementation(libs.llm.langchain4j.ollama)
    implementation(libs.llm.langchain4j.googleGemini)

    testImplementation(project(":testutils"))
}

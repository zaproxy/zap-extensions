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
        extensions {
            register("org.zaproxy.addon.llm.mcp.ExtensionLlmMcp") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.llm.mcp"))
                }
                dependencies {
                    addOns {
                        register("mcp") {
                            version.set(">=0.3.0")
                        }
                    }
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
    zapAddOn("mcp")

    api(libs.llm.langchain4j)
    implementation(libs.llm.langchain4j.anthropic)
    implementation(libs.llm.langchain4j.azureOpenAi)
    implementation(libs.llm.langchain4j.googleGemini)
    implementation(libs.llm.langchain4j.ollama)
    implementation(libs.llm.langchain4j.openAi)

    testImplementation(project(":testutils"))
}

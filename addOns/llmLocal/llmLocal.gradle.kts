description = "An add-on that provides in-process local LLM support via Jlama."

val jlamaNative by configurations.creating
configurations.implementation {
    extendsFrom(jlamaNative)
}

zapAddOn {
    addOnName.set("Local LLM Support")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/llm-local/")

        dependencies {
            javaVersion.set("21")
            addOns {
                register("commonlib") {
                    version.set(">=1.39.0")
                }
                register("llm") {
                    version.set(">=0.0.1")
                }
            }
        }

        bundledLibs {
            libs.from(jlamaNative)
        }
    }
}

crowdin {
    configuration {
        // Package path is lowercase; add-on id is camelCase llmLocal.
        val resourcesPath = "org/zaproxy/addon/llmlocal/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("llm")

    implementation(libs.llm.langchain4j.jlama) {
        // Provided by the llm add-on — must not be duplicated in this .zap
        exclude(group = "dev.langchain4j", module = "langchain4j-core")
    }

    jlamaNative(variantOf(libs.jlama.native) { classifier("linux-x86_64") })
    jlamaNative(variantOf(libs.jlama.native) { classifier("osx-x86_64") })
    jlamaNative(variantOf(libs.jlama.native) { classifier("osx-aarch_64") })
    jlamaNative(variantOf(libs.jlama.native) { classifier("windows-x86_64") })

    testImplementation(project(":testutils"))
}

description = "Displays HTTPS configuration information."

zapAddOn {
    addOnName.set("HttpsInfo")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/https-info-add-on/")
        dependencies {
            addOns {
                register("network") {
                    version.set(">=0.26.0")
                }
            }
        }
    }
}

dependencies {
    testImplementation(project(":testutils"))
    zapAddOn("network")
    implementation(files("lib/DeepViolet-5.9.jar"))
    implementation("com.google.code.gson:gson:2.13.1")
    implementation("org.snakeyaml:snakeyaml-engine:2.8")
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.14.1") {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/zap/extension/httpsinfo/resources/"
        tokens.set(
            mutableMapOf(
                "%addOnId%" to "httpsinfo",
                "%messagesPath%" to resourcesPath,
                "%helpPath%" to resourcesPath,
            ),
        )
    }
}

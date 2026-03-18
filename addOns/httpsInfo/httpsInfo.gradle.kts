description = "Displays HTTPS configuration information."

zapAddOn {
    addOnName.set("HTTPS Info")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/https-info/")
        dependencies {
            javaVersion.set("21")
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
    implementation(libs.httpsinfo.deepviolet)
    implementation(libs.log4j.slf4j)
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

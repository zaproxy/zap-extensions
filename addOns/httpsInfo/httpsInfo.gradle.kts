description = "Displays HTTPS configuration information."

zapAddOn {
    addOnName.set("HTTPS Info")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/https-info/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.40.0 & < 2.0.0")
                }
                register("network") {
                    version.set(">=0.26.0")
                }
            }
        }
    }
}

dependencies {
    testImplementation(project(":testutils"))
    zapAddOn("commonlib")
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

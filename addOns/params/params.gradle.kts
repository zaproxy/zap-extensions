import org.zaproxy.gradle.addon.AddOnStatus

description = "Tracks parameters, cookies, and header values on a site by site basis."

zapAddOn {
    addOnName.set("Params")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/params/")

        dependencies {
            addOns {
                register("pscan") {
                    version.set(">= 0.1.0 & < 1.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.params.ParamsAPI")
    }
}

crowdin {
    configuration {
        val path = "org/zaproxy/addon/params/resources/"
        tokens.put("%messagesPath%", path)
        tokens.put("%helpPath%", path)
    }
}

dependencies {
    zapAddOn("pscan")

    compileOnly("org.zaproxy:zap:2.17.0")

    testImplementation(project(":testutils"))
    testImplementation(libs.log4j.core)
}

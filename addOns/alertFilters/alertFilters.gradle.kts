import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows you to automate the changing of alert risk levels."

zapAddOn {
    addOnName.set("Alert Filters")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/alert-filters/")
        extensions {
            register("org.zaproxy.zap.extension.alertFilters.automation.ExtensionAlertFiltersAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.alertFilters.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.12.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.alertFilters.AlertFilterAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/alertFilters/resources/Messages.properties"))
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    testImplementation(project(":testutils"))
    testImplementation(parent!!.childProjects.get("automation")!!)
}

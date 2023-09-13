import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows you to automate the changing of alert risk levels."

zapAddOn {
    addOnName.set("Alert Filters")
    addOnStatus.set(AddOnStatus.RELEASE)

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
                            version.set(">=0.31.0")
                        }
                        register("commonlib")
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
    zapAddOn("automation")
    zapAddOn("commonlib")

    testImplementation(project(":testutils"))
}

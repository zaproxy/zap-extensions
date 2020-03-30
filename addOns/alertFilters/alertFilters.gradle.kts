import org.zaproxy.gradle.addon.AddOnStatus

version = "11"
description = "Allows you to automate the changing of alert risk levels."

zapAddOn {
    addOnName.set("Alert Filters")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/alert-filters/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.alertFilters.AlertFilterAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/alertFilters/resources/Messages.properties"))
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

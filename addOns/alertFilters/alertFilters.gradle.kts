import org.zaproxy.gradle.addon.AddOnStatus

version = "10"
description = "Allows you to automate the changing of alert risk levels."

zapAddOn {
    addOnName.set("Alert Filters")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.alertFilters.AlertFilterAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/alertFilters/resources/Messages.properties"))
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

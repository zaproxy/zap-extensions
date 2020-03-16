import org.zaproxy.gradle.addon.AddOnStatus

version = "8"
description = "Adds an option to import a file of URLs. The file must be plain text with one URL per line."

zapAddOn {
    addOnName.set("Import files containing URLs")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/import-urls/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.importurls.ImportUrlsAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/importurls/resources/Messages.properties"))
    }
}

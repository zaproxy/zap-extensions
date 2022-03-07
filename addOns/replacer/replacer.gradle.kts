import org.zaproxy.gradle.addon.AddOnStatus

description = "Easy way to replace strings in requests and responses."

zapAddOn {
    addOnName.set("Replacer")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/replacer/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.replacer.ReplacerAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/replacer/resources/Messages.properties"))
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

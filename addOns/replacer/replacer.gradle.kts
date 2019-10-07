import org.zaproxy.gradle.addon.AddOnStatus

version = "8"
description = "Easy way to replace strings in requests and responses."

zapAddOn {
    addOnName.set("Replacer")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.replacer.ReplacerAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/replacer/resources/Messages.properties"))
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

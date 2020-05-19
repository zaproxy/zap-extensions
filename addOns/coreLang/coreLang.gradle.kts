import org.zaproxy.gradle.addon.AddOnStatus

version = "14"
description = "Translations of the core language files"

zapAddOn {
    addOnName.set("Core Language Files")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://crowdin.com/project/owasp-zap")
    }
}

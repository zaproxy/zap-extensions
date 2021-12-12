import org.zaproxy.gradle.addon.AddOnStatus

description = "Translations of the core language files"

zapAddOn {
    addOnName.set("Core Language Files")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://crowdin.com/project/owasp-zap")
    }
}

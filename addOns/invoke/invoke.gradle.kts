import org.zaproxy.gradle.addon.AddOnStatus

description = "Invoke external applications passing context related information such as URLs and parameters"

zapAddOn {
    addOnName.set("Invoke Applications")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/invoke-applications/")
    }
}

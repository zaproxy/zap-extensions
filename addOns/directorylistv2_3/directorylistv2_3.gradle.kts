import org.zaproxy.gradle.addon.AddOnStatus

version = "4"
description = """Lists of directory names to be used with "Forced Browse" add-on."""

zapAddOn {
    addOnName.set("Directory List v2.3")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.owasp.org/index.php/DirBuster")
    }
}

import org.zaproxy.gradle.addon.AddOnStatus

version = "0.0.1"
description = "Import and Export functionality"

zapAddOn {
    addOnName.set("Import/Export")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team & thatsn0tmysite")
        url.set("https://www.zaproxy.org/docs/desktop/addons/import-export/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

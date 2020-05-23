import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Allows to save content of HTTP messages as HAR archive"

zapAddOn {
    addOnName.set("Save Har Message")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/save-har-message/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

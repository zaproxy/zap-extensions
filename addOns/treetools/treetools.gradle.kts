import org.zaproxy.gradle.addon.AddOnStatus

version = "8"
description = "Tools to add functionality to the tree view."

zapAddOn {
    addOnName.set("TreeTools")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("Carl Sampson")
        url.set("https://www.zaproxy.org/docs/desktop/addons/treetools/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

import org.zaproxy.gradle.addon.AddOnStatus

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

crowdin {
    configuration {
        tokens.put("%messagesPath%", "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/")
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

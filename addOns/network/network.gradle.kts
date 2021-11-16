import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides core networking capabilities."

zapAddOn {
    addOnName.set("Network")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/network/")

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
    zap("org.zaproxy:zap:2.11.0")

    testImplementation(project(":testutils"))
}

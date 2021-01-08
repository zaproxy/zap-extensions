import org.zaproxy.gradle.addon.AddOnStatus

version = "0.7.0"
description = "Retire.js"

zapAddOn {
    addOnName.set("Retire.js")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.10.0")

    manifest {
        author.set("Nikita Mundhada and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/retire.js/")
        bundle {
            baseName.set("org.zaproxy.addon.retire.resources.Messages")
            prefix.set("retire")
        }
        helpSet {
            baseName.set("org.zaproxy.addon.retire.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

dependencies {
        implementation("com.google.code.gson:gson:2.8.6")

        testImplementation(project(":testutils"))
}

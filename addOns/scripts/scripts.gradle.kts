import org.zaproxy.gradle.addon.AddOnStatus

version = "29"
description = "Supports all JSR 223 scripting languages"

zapAddOn {
    addOnName.set("Script Console")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/script-console/")
        notBeforeVersion.set("2.10.0")
    }
}

spotless {
    java {
        target(fileTree(projectDir) {
            include("**/*.java")
            // 3rd-party code.
            exclude("**/JScrollPopupMenu.java")
        })
    }
}

import org.zaproxy.gradle.addon.AddOnStatus

version = "5"
description = "Allows to save content of HTTP messages as binary"

zapAddOn {
    addOnName.set("Save Raw Message")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

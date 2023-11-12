import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Allows to test/enumerate the characters allowed in form fields."

zapAddOn {
    addOnName.set("fieldenumeration")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

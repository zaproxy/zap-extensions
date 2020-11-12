import org.zaproxy.gradle.addon.AddOnStatus

version = "0.4.0"
description = "Adds encode/decode/hash dialog and support for scripted processors as well"

zapAddOn {
    addOnName.set("Encoder")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/encode-decode-hash/")
        notBeforeVersion.set("2.10.0")
    }
}

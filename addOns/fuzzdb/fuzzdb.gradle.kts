import org.zaproxy.gradle.addon.AddOnStatus

version = "5"
description = "FuzzDB files which can be used with the ZAP fuzzer"

zapAddOn {
    addOnName.set("FuzzDB files")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/fuzzdb-project/fuzzdb/")
    }
}

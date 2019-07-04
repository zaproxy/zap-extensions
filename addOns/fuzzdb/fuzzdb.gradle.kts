import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    eclipse
}

eclipse {
    classpath {
        // Prevent compilation of zapHomeFiles.
        sourceSets = listOf()
    }
}

version = "6"
description = "FuzzDB files which can be used with the ZAP fuzzer"

zapAddOn {
    addOnName.set("FuzzDB files")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://github.com/fuzzdb-project/fuzzdb/")
    }
}

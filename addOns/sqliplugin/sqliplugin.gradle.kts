import org.zaproxy.gradle.addon.AddOnStatus

version = "13"
description = "An advanced active injection bundle for SQLi (derived by SQLMap)"

zapAddOn {
    addOnName.set("Advanced SQLInjection Scanner")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.5.0")

    manifest {
        author.set("Andrea Pompili (Yhawke)")
    }
}

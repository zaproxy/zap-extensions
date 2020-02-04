import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Mongodb vuln scanner"

zapAddOn {
    addOnName.set("mongodb")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        author.set("Akila Weeratunga")
        url.set("https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsOnlineMenuOnlineMenu")
    }
}

dependencies {
    implementation("org.jsoup:jsoup:1.12.1")
    implementation("org.json:json:20190722")
}

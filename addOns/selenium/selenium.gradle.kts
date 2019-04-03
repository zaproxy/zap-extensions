import org.zaproxy.gradle.addon.AddOnStatus

version = "15"
description = "WebDriver provider and includes HtmlUnit browser"

zapAddOn {
    addOnName.set("Selenium")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.7.0")

    manifest {
        semVer.set("2.0.0")
        author.set("ZAP Dev Team")
    }
}

dependencies {
    api("org.seleniumhq.selenium:selenium-server:3.7.1")

    testImplementation(project(":testutils"))
}

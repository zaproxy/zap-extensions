import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.tasks.DownloadWebDriver

version = "9"
description = "Linux WebDrivers for Firefox and Chrome."

extra["targetOs"] = DownloadWebDriver.OS.LINUX

zapAddOn {
    addOnName.set("Linux WebDrivers")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
        helpSet {
            baseName.set("org.zaproxy.zap.extension.webdriverlinux.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

tasks {
    register<DownloadWebDriver>("downloadChromeDriver") {
        browser.set(DownloadWebDriver.Browser.CHROME)
        arch.set(DownloadWebDriver.Arch.X64)
    }

    register<DownloadWebDriver>("downloadGeckodriverX32") {
        browser.set(DownloadWebDriver.Browser.FIREFOX)
        arch.set(DownloadWebDriver.Arch.X32)
    }

    register<DownloadWebDriver>("downloadGeckodriverX64") {
        browser.set(DownloadWebDriver.Browser.FIREFOX)
        arch.set(DownloadWebDriver.Arch.X64)
    }
}

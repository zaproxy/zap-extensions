import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.tasks.DownloadWebDriver

version = "23"
description = "MacOS WebDrivers for Firefox and Chrome."

extra["targetOs"] = DownloadWebDriver.OS.MAC

zapAddOn {
    addOnName.set("MacOS WebDrivers")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/macos-webdrivers/")
        helpSet {
            baseName.set("org.zaproxy.zap.extension.webdrivermacos.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

tasks {
    register<DownloadWebDriver>("downloadChromeDriver") {
        browser.set(DownloadWebDriver.Browser.CHROME)
        arch.set(DownloadWebDriver.Arch.X64)
    }

    register<DownloadWebDriver>("downloadGeckodriver") {
        browser.set(DownloadWebDriver.Browser.FIREFOX)
        arch.set(DownloadWebDriver.Arch.X64)
    }
}

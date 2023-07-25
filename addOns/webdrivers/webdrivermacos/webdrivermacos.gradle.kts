import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.tasks.DownloadWebDriver

description = "MacOS WebDrivers for Firefox and Chrome."

extra["targetOs"] = DownloadWebDriver.OS.MAC

zapAddOn {
    addOnName.set("MacOS WebDrivers")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/macos-webdrivers/")
        helpSet {
            baseName.set("org.zaproxy.zap.extension.webdrivermacos.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

tasks.named(AddOnPlugin.GENERATE_MANIFEST_TASK_NAME) {
    dependsOn(tasks.withType<DownloadWebDriver>())
}

tasks {
    register<DownloadWebDriver>("downloadChromeDriver") {
        browser.set(DownloadWebDriver.Browser.CHROME)
        arch.set(DownloadWebDriver.Arch.X64)
    }

    register<DownloadWebDriver>("downloadChromeDriverArm") {
        browser.set(DownloadWebDriver.Browser.CHROME)
        arch.set(DownloadWebDriver.Arch.ARM64)
    }

    register<DownloadWebDriver>("downloadGeckodriver") {
        browser.set(DownloadWebDriver.Browser.FIREFOX)
        arch.set(DownloadWebDriver.Arch.X64)
    }

    register<DownloadWebDriver>("downloadGeckodriverArm") {
        browser.set(DownloadWebDriver.Browser.FIREFOX)
        arch.set(DownloadWebDriver.Arch.ARM64)
    }
}

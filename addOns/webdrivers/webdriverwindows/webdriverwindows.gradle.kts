import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.tasks.DownloadWebDriver

description = "Windows WebDrivers for Firefox and Chrome."

extra["targetOs"] = DownloadWebDriver.OS.WIN

zapAddOn {
    addOnName.set("Windows WebDrivers")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/windows-webdrivers/")
        helpSet {
            baseName.set("org.zaproxy.zap.extension.webdriverwindows.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

tasks.named(AddOnPlugin.GENERATE_MANIFEST_TASK_NAME) {
    dependsOn(tasks.withType<DownloadWebDriver>())
}

tasks {
    register<DownloadWebDriver>("downloadChromeDriverX32") {
        browser.set(DownloadWebDriver.Browser.CHROME)
        arch.set(DownloadWebDriver.Arch.X32)
    }

    register<DownloadWebDriver>("downloadChromeDriverX64") {
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

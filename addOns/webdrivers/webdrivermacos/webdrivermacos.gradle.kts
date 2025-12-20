import org.zaproxy.gradle.WebDriverData
import org.zaproxy.gradle.addon.AddOnStatus

description = "macOS WebDrivers for Firefox and Chrome."

extra["webdrivers"] =
    listOf(
        WebDriverData(WebDriverData.OS.MAC, WebDriverData.Browser.CHROME, WebDriverData.Arch.X64),
        WebDriverData(WebDriverData.OS.MAC, WebDriverData.Browser.CHROME, WebDriverData.Arch.ARM64),
        WebDriverData(WebDriverData.OS.MAC, WebDriverData.Browser.FIREFOX, WebDriverData.Arch.X64, false),
        WebDriverData(WebDriverData.OS.MAC, WebDriverData.Browser.FIREFOX, WebDriverData.Arch.ARM64, false),
    )

zapAddOn {
    addOnName.set("macOS WebDrivers")
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

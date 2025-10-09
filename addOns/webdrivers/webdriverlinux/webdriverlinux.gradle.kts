import org.zaproxy.gradle.WebDriverData
import org.zaproxy.gradle.addon.AddOnStatus

description = "Linux WebDrivers for Firefox and Chrome."

extra["webdrivers"] =
    listOf(
        WebDriverData(WebDriverData.OS.LINUX, WebDriverData.Browser.CHROME, WebDriverData.Arch.X64),
        WebDriverData(WebDriverData.OS.LINUX, WebDriverData.Browser.FIREFOX, WebDriverData.Arch.X32, false),
        WebDriverData(WebDriverData.OS.LINUX, WebDriverData.Browser.FIREFOX, WebDriverData.Arch.X64, false),
        WebDriverData(WebDriverData.OS.LINUX, WebDriverData.Browser.FIREFOX, WebDriverData.Arch.ARM64, false),
    )

zapAddOn {
    addOnName.set("Linux WebDrivers")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/linux-webdrivers/")
        helpSet {
            baseName.set("org.zaproxy.zap.extension.webdriverlinux.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

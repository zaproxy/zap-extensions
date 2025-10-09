import org.zaproxy.gradle.WebDriverData
import org.zaproxy.gradle.addon.AddOnStatus

description = "Windows WebDrivers for Firefox and Chrome."

extra["webdrivers"] =
    listOf(
        WebDriverData(WebDriverData.OS.WIN, WebDriverData.Browser.CHROME, WebDriverData.Arch.X32),
        WebDriverData(WebDriverData.OS.WIN, WebDriverData.Browser.CHROME, WebDriverData.Arch.X64),
        WebDriverData(WebDriverData.OS.WIN, WebDriverData.Browser.FIREFOX, WebDriverData.Arch.X32),
        WebDriverData(WebDriverData.OS.WIN, WebDriverData.Browser.FIREFOX, WebDriverData.Arch.X64),
    )

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

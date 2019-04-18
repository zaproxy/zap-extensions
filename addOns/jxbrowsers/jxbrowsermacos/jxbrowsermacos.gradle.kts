import org.zaproxy.gradle.tasks.DownloadWebDriver

version = "12"

extra["osName"] = "Mac OS"
extra["osDep"] = "mac"
extra["extClass"] = "org.zaproxy.zap.extension.jxbrowsermacos.selenium.ExtSelJxBrowserMacOs"
extra["webDriverOs"] = DownloadWebDriver.OS.MAC
extra["webDriverArch"] = DownloadWebDriver.Arch.X64

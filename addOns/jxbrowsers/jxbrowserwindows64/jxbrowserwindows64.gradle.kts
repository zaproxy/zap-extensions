import org.zaproxy.gradle.tasks.DownloadWebDriver

version = "5"

extra["osName"] = "Windows 64bits"
extra["osDep"] = "win64"
extra["extClass"] = "org.zaproxy.zap.extension.jxbrowserwindows64.selenium.ExtSelJxBrowserWindows64"
extra["webDriverOs"] = DownloadWebDriver.OS.WIN
extra["webDriverArch"] = DownloadWebDriver.Arch.X32

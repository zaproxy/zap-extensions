import org.zaproxy.gradle.tasks.DownloadWebDriver

version = "12"

extra["osName"] = "Windows"
extra["osDep"] = "win32"
extra["extClass"] = "org.zaproxy.zap.extension.jxbrowserwindows.selenium.ExtSelJxBrowserWindows"
extra["webDriverOs"] = DownloadWebDriver.OS.WIN
extra["webDriverArch"] = DownloadWebDriver.Arch.X32

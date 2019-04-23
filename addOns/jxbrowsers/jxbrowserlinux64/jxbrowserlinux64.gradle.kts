import org.zaproxy.gradle.tasks.DownloadWebDriver

version = "12"

extra["osName"] = "Linux 64"
extra["osDep"] = "linux64"
extra["extClass"] = "org.zaproxy.zap.extension.jxbrowserlinux64.selenium.ExtSelJxBrowserLinux64"
extra["webDriverOs"] = DownloadWebDriver.OS.LINUX
extra["webDriverArch"] = DownloadWebDriver.Arch.X64

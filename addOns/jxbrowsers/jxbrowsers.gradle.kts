import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.tasks.DownloadWebDriver

description = "Common configuration of the JxBrowser add-ons."

val jxBrowserVersion = "6.23.1"
val chromeDriverVersion = "2.44"

subprojects {
    repositories {
        maven("https://maven.teamdev.com/repository/products")
    }

    zapAddOn {
        zapVersion.set("2.7.0")

        manifest {
            author.set("ZAP Dev Team")
        }
    }

    val osSpecificAddOn = project.name != "jxbrowser"

    dependencies {
        if (osSpecificAddOn) {
            "compileOnly"(parent!!.childProjects.get("jxbrowser")!!)
            "compileOnly"(parent!!.parent!!.childProjects.get("selenium")!!)
        } else {
            "implementation"(files("lib/licence.jar"))
            "api"("com.teamdev.jxbrowser:jxbrowser:$jxBrowserVersion")
        }
    }

    afterEvaluate {
        if (osSpecificAddOn) {
            val osName = project.extra["osName"]
            val osDep = project.extra["osDep"]
            val extClass = project.extra["extClass"]

            description = "An embedded browser based on Chromium, $osName specific"

            val webDriverOs = project.extra["webDriverOs"] as DownloadWebDriver.OS
            val webDriverArch = project.extra["webDriverArch"] as DownloadWebDriver.Arch
            val webdriverDir = file("$buildDir/webdriver/")

            val downloadTask by tasks.registering(DownloadWebDriver::class) {
                var path = "jxbrowser/webdriver/"
                path += when (webDriverOs) {
                    DownloadWebDriver.OS.LINUX -> "linux"
                    DownloadWebDriver.OS.MAC -> "macos"
                    DownloadWebDriver.OS.WIN -> "windows"
                }
                path += "/chromedriver"
                if (webDriverOs == DownloadWebDriver.OS.WIN) {
                    path += ".exe"
                }

                os.set(webDriverOs)
                arch.set(webDriverArch)
                browser.set(DownloadWebDriver.Browser.CHROME)
                version.set(chromeDriverVersion)
                outputFile.set(File(webdriverDir, path))
            }

            sourceSets["main"].output.dir(mapOf("builtBy" to downloadTask), webdriverDir)

            zapAddOn {
                addOnName.set("JxBrowser ($osName)")

                manifest {
                    files.from(webdriverDir)

                    dependencies {
                        addOns {
                            register("jxbrowser")
                        }
                    }

                    extensions {
                        register("$extClass") {
                            dependencies {
                                addOns {
                                    register("selenium") {
                                        semVer.set(" >=2.0.0 & <3.0.0 ")
                                    }
                                }
                            }
                        }
                    }
                }
            }

            dependencies {
                "runtimeOnly"("com.teamdev.jxbrowser:jxbrowser-$osDep:$jxBrowserVersion") {
                    // Provided by the JxBrowser (core) add-on.
                    exclude(group = "com.teamdev.jxbrowser", module = "jxbrowser")
                }
            }
        }
    }
}

val Project.sourceSets: org.gradle.api.tasks.SourceSetContainer get() =
    (this as ExtensionAware).extensions.getByName("sourceSets") as SourceSetContainer

fun Project.zapAddOn(configure: AddOnPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("zapAddOn", configure)

fun AddOnPluginExtension.manifest(configure: ManifestExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("manifest", configure)

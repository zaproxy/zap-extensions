import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.crowdin.CrowdinExtension
import org.zaproxy.gradle.tasks.DownloadWebDriver

description = "Common configuration of the WebDriver add-ons."

val geckodriverVersion = "0.29.1"
val chromeDriverVersion = "93.0.4577.15"

fun configureDownloadTask(outputDir: File, targetOs: DownloadWebDriver.OS, task: DownloadWebDriver) {
    val geckodriver = task.browser.get() == DownloadWebDriver.Browser.FIREFOX
    var path = "webdriver/"
    path += when (targetOs) {
        DownloadWebDriver.OS.LINUX -> "linux"
        DownloadWebDriver.OS.MAC -> "macos"
        DownloadWebDriver.OS.WIN -> "windows"
    }
    path += "/"
    path += if (task.arch.get() == DownloadWebDriver.Arch.X32) "32" else "64"
    path += "/"
    path += if (geckodriver) "geckodriver" else "chromedriver"
    if (targetOs == DownloadWebDriver.OS.WIN) {
        path += ".exe"
    }

    with(task) {
        os.set(targetOs)
        version.set(if (geckodriver) geckodriverVersion else chromeDriverVersion)
        outputFile.set(File(outputDir, path))
    }
}

subprojects {
    crowdin {
        configuration {
            file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        }
    }

    afterEvaluate {
        val webdriversDir = file("$buildDir/webdrivers/")
        val targetOs = project.extra["targetOs"] as DownloadWebDriver.OS

        val downloadTasks = tasks.withType<DownloadWebDriver>().also {
            it.configureEach {
                configureDownloadTask(webdriversDir, targetOs, this)
            }
        }

        sourceSets["main"].output.dir(mapOf("builtBy" to downloadTasks), webdriversDir)

        zapAddOn {
            manifest {
                files.from(webdriversDir)
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

fun Project.crowdin(configure: CrowdinExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("crowdin", configure)

val Project.crowdin: CrowdinExtension get() =
    (this as ExtensionAware).extensions.getByName("crowdin") as CrowdinExtension

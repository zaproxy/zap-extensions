import de.undercouch.gradle.tasks.download.Download
import org.zaproxy.gradle.WebDriverData
import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.crowdin.CrowdinExtension

plugins {
    alias(libs.plugins.undercouch.download)
}

description = "Common configuration of the WebDriver add-ons."

val geckodriverVersion = project.property("zap.geckodriver.version") as String
val chromeDriverVersion = project.property("zap.chromedriver.version") as String

fun downloadUrl(data: WebDriverData): String {
    if (data.browser == WebDriverData.Browser.FIREFOX) {
        val filename =
            when (data.os) {
                WebDriverData.OS.LINUX -> {
                    when (data.arch) {
                        WebDriverData.Arch.X32 -> "linux32.tar.gz"
                        WebDriverData.Arch.X64 -> "linux64.tar.gz"
                        WebDriverData.Arch.ARM64 -> "linux-aarch64.tar.gz"
                    }
                }
                WebDriverData.OS.MAC -> "macos${if (data.arch == WebDriverData.Arch.X64) "" else "-aarch64"}.tar.gz"
                WebDriverData.OS.WIN -> "win${data.arch.str}.zip"
            }

        return "https://github.com/mozilla/geckodriver/releases/download/" +
            "v$geckodriverVersion/${data.browser.webdriver}-v$geckodriverVersion-$filename"
    }

    val arch =
        when (data.os) {
            WebDriverData.OS.LINUX -> "linux${data.arch.str}"
            WebDriverData.OS.MAC ->
                "mac-${if (data.arch == WebDriverData.Arch.X64) "x" else ""}${data.arch.str}"
            WebDriverData.OS.WIN -> "win${data.arch.str}"
        }

    return "https://storage.googleapis.com/chrome-for-testing-public/" +
        "$chromeDriverVersion/$arch/${data.browser.webdriver}-$arch.zip"
}

fun webDriverDir(data: WebDriverData) = "webdriver/${data.os.str}/${data.arch.str}/"

fun webDriverPackageName(data: WebDriverData): String {
    val version = if (data.browser == WebDriverData.Browser.FIREFOX) geckodriverVersion else chromeDriverVersion
    val extension = if (data.zipped) "zip" else "tar.gz"
    return "${data.browser.webdriver}-v$version-${data.os.str}${data.arch.str}.$extension"
}

fun webDriverPath(data: WebDriverData) = webDriverDir(data) + "${data.browser.webdriver}"

subprojects {
    apply(plugin = "de.undercouch.download")

    crowdin {
        configuration {
            file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        }
    }

    afterEvaluate {
        val webdriversDir = layout.buildDirectory.dir("webdrivers")

        val webdriversPackagedDir: Provider<Directory> =
            System.getenv("ZAP_WD_CACHE")?.let {
                provider { layout.projectDirectory.dir("${gradle.gradleUserHomeDir}/caches/zap-wd") }
            } ?: layout.buildDirectory.dir("webdriversPackaged")

        @Suppress("UNCHECKED_CAST")
        val webdrivers = project.extra["webdrivers"] as List<WebDriverData>

        val copyTasks = mutableListOf<TaskProvider<Copy>>()
        webdrivers.forEach { data ->

            val baseTaskName = "${capitalized(data.browser)}Driver${capitalized(data.arch)}"
            val downloadTask =
                tasks.register<Download>("download$baseTaskName") {
                    src(downloadUrl(data))
                    dest(webdriversPackagedDir.map { it.file(webDriverPackageName(data)) })
                    connectTimeout(60_000)
                    readTimeout(60_000)
                    onlyIfModified(true)
                }

            val copyTask =
                tasks.register<Copy>("copy$baseTaskName") {
                    val packagedFile = downloadTask.map { it.outputs.files.singleFile }
                    val source = if (data.zipped) zipTree(packagedFile) else tarTree(packagedFile)
                    from(source) {
                        include("**/${data.browser.webdriver}*")
                        eachFile {
                            setPath(relativePath.lastName)
                        }
                    }
                    into(webdriversDir.map { it.dir(webDriverDir(data)) })
                }

            copyTasks.add(copyTask)
        }

        tasks.named(AddOnPlugin.GENERATE_MANIFEST_TASK_NAME) {
            dependsOn(copyTasks)
        }

        sourceSets["main"].output.dir(mapOf("builtBy" to copyTasks), webdriversDir)

        zapAddOn {
            manifest {
                files.from(webdriversDir)
            }
        }
    }
}

fun capitalized(a: Any) = a.toString().lowercase().replaceFirstChar(Char::titlecase)

val Project.sourceSets: org.gradle.api.tasks.SourceSetContainer get() =
    (this as ExtensionAware).extensions.getByName("sourceSets") as SourceSetContainer

fun Project.zapAddOn(configure: AddOnPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("zapAddOn", configure)

fun AddOnPluginExtension.manifest(configure: ManifestExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("manifest", configure)

fun Project.crowdin(configure: CrowdinExtension.() -> Unit): Unit = (this as ExtensionAware).extensions.configure("crowdin", configure)

val Project.crowdin: CrowdinExtension get() =
    (this as ExtensionAware).extensions.getByName("crowdin") as CrowdinExtension

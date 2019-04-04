import java.nio.charset.StandardCharsets
import org.apache.commons.codec.digest.DigestUtils
import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.tasks.DownloadWebDriver

description = "Common configuration of the JxBrowser add-ons."

val jxBrowserVersion = "6.23.1"
val chromeDriverVersion = "2.44"

val libsHashes = mapOf(
    "jxbrowser-$jxBrowserVersion.jar" to "5f3d17e393720073cd00d6e1d71684977fccf039eb1a232f364e06bfd066310f",
    "jxbrowser-linux64-$jxBrowserVersion.jar" to "8c0c5e12ebbebe4165ace0a66bba6c94d465a7f748503b008aae0cde280a1c76",
    "jxbrowser-mac-$jxBrowserVersion.jar" to "155be52076298448d47ec537ba512a2cc719e2b91aefa2f4c2ad47d1753a8a19",
    "jxbrowser-win32-$jxBrowserVersion.jar" to "77e8c8d03f28e4555795304f4a4873284e1325b22248299fcd9ffedb8d457894",
    "jxbrowser-win64-$jxBrowserVersion.jar" to "fdfc31ea4748019f8ec004b7f30d0cb8812d71486fe9a3e2694be04b8324fef6"
)

subprojects {
    repositories {
        // TODO use HTTPS when available (and remove lib hash checks)
        maven("http://maven.teamdev.com/repository/products")
    }

    zapAddOn {
        zapVersion.set("2.7.0")

        manifest {
            author.set("ZAP Dev Team")
        }
    }

    val validateLibraries by tasks.registering(ValidateLibs::class) {
        expectedHashes.set(libsHashes)
        computedHashes.set(project.layout.buildDirectory.file("libsHashes.txt"))
        libs.from(configurations["runtimeClasspath"])
    }

    tasks.named("compileJava") {
        dependsOn(validateLibraries)
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

open class ValidateLibs : DefaultTask() {

    @get:InputFiles
    val libs = project.files()

    @get:Input
    val expectedHashes = project.objects.mapProperty<String, String>()

    @get:OutputFile
    val computedHashes = project.objects.fileProperty()

    @TaskAction
    fun validate() {
        val hashesMap = expectedHashes.get()
        val outputFile = computedHashes.get().getAsFile()
        libs.files.forEach { lib ->
            hashesMap.get(lib.name)?.let {
                val computedHash = hash(lib)
                if (it != computedHash) {
                    throw AssertionError("Hash mismatch for library $lib expected $it but got $computedHash")
                }
                outputFile.writeText("${lib.name}:$it\n", StandardCharsets.UTF_8)
            }
        }
    }

    fun hash(file: File) = file.inputStream().use { DigestUtils.sha256Hex(it) }
}

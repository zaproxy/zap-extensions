import java.nio.charset.StandardCharsets
import org.apache.commons.codec.digest.DigestUtils
import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.tasks.DownloadWebDriver

description = "Common configuration of the JxBrowser add-ons."

val jxBrowserVersion = "6.23"
val chromeDriverVersion = "2.44"

val libsHashes = mapOf(
    "jxbrowser-$jxBrowserVersion.jar" to "c1643df3628ef74c29a5f1974afb158197efed11535d9e69ac12ded7cef2ebfe",
    "jxbrowser-linux64-$jxBrowserVersion.jar" to "534ccde4475fbb80b7c40f8a355f17282d50a30697bdee1e25e69326818ccd50",
    "jxbrowser-mac-$jxBrowserVersion.jar" to "069d9dc3392e6700f5c3a8fb11cac7c0541197b5da28e6295561d4fc53200136",
    "jxbrowser-win32-$jxBrowserVersion.jar" to "44a342bb39858ea9d751faa82432d66e39481f4cda84bb72eb7f43ce09f6d048",
    "jxbrowser-win64-$jxBrowserVersion.jar" to "102cb713f861788de17769d5e5bb99991e39465531191aa400d50fbc1d49ee54"
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

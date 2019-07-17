import java.nio.charset.StandardCharsets
import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.apigen.ApiClientGenExtension
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml
import org.zaproxy.gradle.addon.misc.CreateGitHubRelease
import org.zaproxy.gradle.addon.misc.ExtractLatestChangesFromChangelog
import org.zaproxy.gradle.addon.wiki.WikiGenExtension

plugins {
    jacoco
    id("org.zaproxy.add-on") version "0.2.0" apply false
}

description = "Common configuration of the add-ons."

val zapCoreHelpWikiDir = "$rootDir/../zap-core-help-wiki/"
val zapExtensionsWikiDir = "$rootDir/../zap-extensions-wiki/"

val parentProjects = listOf(
    "webdrivers"
)

val addOnsInZapCoreHelp = listOf(
    "alertFilters",
    "ascanrules",
    "bruteforce",
    "coreLang",
    "diff",
    "directorylistv1",
    "fuzz",
    "gettingStarted",
    "importurls",
    "invoke",
    "onlineMenu",
    "pscanrules",
    "quickstart",
    "replacer",
    "reveal",
    "saverawmessage",
    "savexmlmessage",
    "scripts",
    "selenium",
    "spiderAjax",
    "tips",
    "webdriverlinux",
    "webdrivermacos",
    "webdriverwindows",
    "websocket",
    "zest"
)

val jacocoToolVersion = "0.8.4"
jacoco {
    toolVersion = jacocoToolVersion
}

subprojects {
    if (parentProjects.contains(project.name)) {
        return@subprojects
    }

    apply(plugin = "java-library")
    apply(plugin = "jacoco")
    apply(plugin = "org.zaproxy.add-on")

    java {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    jacoco {
        toolVersion = jacocoToolVersion
    }

    val apiGenClasspath = configurations.detachedConfiguration(dependencies.create("org.zaproxy:zap:2.8.0"))

    zapAddOn {
        releaseLink.set(project.provider { "https://github.com/zaproxy/zap-extensions/releases/${zapAddOn.addOnId.get()}-v@CURRENT_VERSION@" })

        manifest {
            changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
        }

        wikiGen {
            wikiFilesPrefix.set("HelpAddons${zapAddOn.addOnId.get().capitalize()}")
            wikiDir.set(project.provider { project.layout.projectDirectory.dir(if (addOnsInZapCoreHelp.contains(zapAddOn.addOnId.get())) zapCoreHelpWikiDir else zapExtensionsWikiDir) })
        }

        apiClientGen {
            classpath.run {
                setFrom(apiGenClasspath)
                from(tasks.named(JavaPlugin.JAR_TASK_NAME))
            }
        }
    }
}

tasks.register<TestReport>("testReport") {
    destinationDir = file("$buildDir/reports/allTests")
    subprojects.forEach {
        it.plugins.withType(JavaPlugin::class) {
            reportOn(it.tasks.withType<Test>())
        }
    }

    doLast {
        val reportUrl = File(destinationDir, "index.html").toURL()
        logger.lifecycle("Test Report: $reportUrl")
    }
}

val jacocoMerge by tasks.registering(JacocoMerge::class) {
    destinationFile = file("$buildDir/jacoco/all.exec")
    subprojects.forEach {
        it.plugins.withType(JavaPlugin::class) {
            executionData(it.tasks.withType<Test>())
        }
    }

    doFirst {
        executionData = files(executionData.files.filter { it.exists() })
    }
}

val jacocoReport by tasks.registering(JacocoReport::class) {
    executionData(jacocoMerge)
    subprojects.forEach {
        it.plugins.withType(JavaPlugin::class) {
            val sourceSets = it.extensions.getByName("sourceSets") as SourceSetContainer
            sourceDirectories.from(files(sourceSets["main"].java.srcDirs))
            classDirectories.from(files(sourceSets["main"].output.classesDirs))
        }
    }

    doLast {
        val reportUrl = File(reports.html.destination, "index.html").toURL()
        logger.lifecycle("Coverage Report: $reportUrl")
    }
}

System.getenv("GITHUB_REF")?.let { ref ->
    if ("refs/tags/" !in ref || !ref.contains(Regex(".*-v.*"))) {
        return@let
    }

    tasks.register<CreateGitHubRelease>("createReleaseFromGitHubRef") {
        val targetTag = ref.removePrefix("refs/tags/")
        val (targetAddOnId, targetAddOnVersion) = targetTag.split("-v")
        val addOnProject = subproject(targetAddOnId)

        authToken.set(System.getenv("GITHUB_TOKEN"))
        repo.set(System.getenv("GITHUB_REPOSITORY"))
        tag.set(targetTag)

        title.set(addOnProject.map { "${it.zapAddOn.addOnName.get()} version ${it.zapAddOn.addOnVersion.get()}" })
        bodyFile.set(addOnProject.flatMap { it.tasks.named<ExtractLatestChangesFromChangelog>("extractLatestChanges").flatMap { it.latestChanges } })

        assets {
            register("add-on") {
                file.set(addOnProject.flatMap { it.tasks.named<Jar>(AddOnPlugin.JAR_ZAP_ADD_ON_TASK_NAME).flatMap { it.archiveFile } })
            }
        }

        doFirst {
            val addOnVersion = addOnProject.get().zapAddOn.addOnVersion.get()
            require(addOnVersion == targetAddOnVersion) {
                "Version of the tag $targetAddOnVersion does not match the version of the add-on $addOnVersion"
            }
        }
    }
}

fun subprojects(addOns: List<String>, action: (Project) -> Unit) {
    subprojects.filter { !parentProjects.contains(it.name) && addOns.contains(it.zapAddOn.addOnId.get()) }.forEach(action)
}

fun subproject(addOnId: String): Provider<Project> =
    project.provider {
        val addOnProject = subprojects.firstOrNull { it.name !in parentProjects && addOnId == it.zapAddOn.addOnId.get() }
        require(addOnProject != null) { "Add-on with ID $addOnId not found." }
        addOnProject
    }

fun Project.java(configure: JavaPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("java", configure)

fun Project.jacoco(configure: JacocoPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("jacoco", configure)

fun Project.zapAddOn(configure: AddOnPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("zapAddOn", configure)

val Project.zapAddOn: AddOnPluginExtension get() =
    (this as ExtensionAware).extensions.getByName("zapAddOn") as AddOnPluginExtension

fun AddOnPluginExtension.manifest(configure: ManifestExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("manifest", configure)

fun AddOnPluginExtension.wikiGen(configure: WikiGenExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("wikiGen", configure)

fun AddOnPluginExtension.apiClientGen(configure: ApiClientGenExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("apiClientGen", configure)

open class ValidateDeclaredAddOns : DefaultTask() {

    init {
        group = LifecycleBasePlugin.VERIFICATION_GROUP
        description = "Verifies that the declared weekly/main add-ons exist."
    }

    @get:Input
    val declaredAddOns = project.objects.setProperty<String>()

    @get:Input
    val addOns = project.objects.setProperty<String>()

    @get:OutputFile
    val validatedAddOns = project.objects.fileProperty()

    @TaskAction
    fun validate() {
        val missingDeclaredAddOns = declaredAddOns.get() - addOns.get()
        if (!missingDeclaredAddOns.isEmpty()) {
            throw IllegalStateException("The following declared add-ons do not exist: $missingDeclaredAddOns")
        }

        validatedAddOns.get().getAsFile().writeText("${declaredAddOns.get()}", StandardCharsets.UTF_8)
    }
}

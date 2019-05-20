import java.nio.charset.StandardCharsets
import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml
import org.zaproxy.gradle.addon.misc.CreateGitHubRelease
import org.zaproxy.gradle.addon.misc.ExtractLatestChangesFromChangelog
import org.zaproxy.gradle.addon.wiki.WikiGenExtension

plugins {
    id("org.zaproxy.add-on") version "0.2.0" apply false
}

description = "Common configuration of the add-ons."

val zapCoreHelpWikiDir = "$rootDir/../zap-core-help-wiki/"
val zapExtensionsWikiDir = "$rootDir/../zap-extensions-wiki/"

val parentProjects = listOf(
    "jxbrowsers",
    "webdrivers"
)

val mainAddOns = listOf(
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
    "jxbrowser",
    "jxbrowserlinux64",
    "jxbrowsermacos",
    "jxbrowserwindows",
    "jxbrowserwindows64",
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
val weeklyAddOns = mainAddOns + listOf(
    "accessControl",
    "ascanrulesBeta",
    "formhandler",
    "openapi",
    "plugnhack",
    "portscan",
    "pscanrulesBeta",
    "sequence"
)

val verifyDeclaredAddOnsExist by tasks.registering(ValidateDeclaredAddOns::class) {
    declaredAddOns.addAll(mainAddOns)
    declaredAddOns.addAll(weeklyAddOns)
    addOns.set(subprojects.filter { !parentProjects.contains(it.name) }.mapTo(mutableSetOf(), { it.zapAddOn.addOnId.get() }))
    validatedAddOns.set(project.layout.buildDirectory.file("validatedAddOns"))
}

tasks.check {
    dependsOn(verifyDeclaredAddOnsExist)
}

mapOf("main" to mainAddOns, "weekly" to weeklyAddOns).forEach { entry ->
    tasks {
        val name = entry.key
        val nameCapitalized = name.capitalize()
        register("copy${nameCapitalized}AddOns") {
            group = "ZAP"
            description = "Copies the $name release add-ons to zaproxy project."
            dependsOn(verifyDeclaredAddOnsExist)
            subprojects(entry.value) {
                dependsOn(it.tasks.named(AddOnPlugin.COPY_ADD_ON_TASK_NAME))
            }
        }

        register("list${nameCapitalized}AddOns") {
            group = "ZAP"
            description = "Lists the $name release add-ons."
            doLast {
                subprojects(entry.value) { println(it.name) }
            }
        }
    }
}

subprojects {
    if (parentProjects.contains(project.name)) {
        return@subprojects
    }

    apply(plugin = "java-library")
    apply(plugin = "org.zaproxy.add-on")

    java {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    zapAddOn {
        releaseLink.set(project.provider { "https://github.com/zaproxy/zap-extensions/releases/${zapAddOn.addOnId.get()}-v@CURRENT_VERSION@" })

        manifest {
            changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
        }

        wikiGen {
            wikiFilesPrefix.set("HelpAddons${zapAddOn.addOnId.get().capitalize()}")
            wikiDir.set(project.provider { project.layout.projectDirectory.dir(if (mainAddOns.contains(zapAddOn.addOnId.get())) zapCoreHelpWikiDir else zapExtensionsWikiDir) })
        }
    }
}

System.getenv("GITHUB_REF")?.let { ref ->
    if ("refs/tags/" !in ref) {
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

fun Project.zapAddOn(configure: AddOnPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("zapAddOn", configure)

val Project.zapAddOn: AddOnPluginExtension get() =
    (this as ExtensionAware).extensions.getByName("zapAddOn") as AddOnPluginExtension

fun AddOnPluginExtension.manifest(configure: ManifestExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("manifest", configure)

fun AddOnPluginExtension.wikiGen(configure: WikiGenExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("wikiGen", configure)

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

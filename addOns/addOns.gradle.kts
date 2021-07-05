import java.util.Locale
import java.util.regex.Pattern
import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnPluginExtension
import org.zaproxy.gradle.addon.apigen.ApiClientGenExtension
import org.zaproxy.gradle.addon.internal.GitHubReleaseExtension
import org.zaproxy.gradle.addon.internal.model.AddOnRelease
import org.zaproxy.gradle.addon.internal.model.ProjectInfo
import org.zaproxy.gradle.addon.internal.model.ReleaseState
import org.zaproxy.gradle.addon.internal.tasks.CreatePullRequest
import org.zaproxy.gradle.addon.internal.tasks.CreateTagAndGitHubRelease
import org.zaproxy.gradle.addon.internal.tasks.GenerateReleaseStateLastCommit
import org.zaproxy.gradle.addon.internal.tasks.HandleRelease
import org.zaproxy.gradle.addon.manifest.ManifestExtension
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    eclipse
    jacoco
    id("org.zaproxy.add-on") version "0.6.0" apply false
}

description = "Common configuration of the add-ons."

val parentProjects = listOf(
    "webdrivers"
)

val jacocoToolVersion = "0.8.5"
jacoco {
    toolVersion = jacocoToolVersion
}

val ghReleaseDataProvider = provider {
    subprojects.first().zapAddOn.gitHubRelease
}
val generateReleaseStateLastCommit by tasks.registering(GenerateReleaseStateLastCommit::class)

val handleRelease by tasks.registering(HandleRelease::class) {
    user.set(ghReleaseDataProvider.map { it.user.get() })
    repo.set(ghReleaseDataProvider.map { it.marketplaceRepo.get() })
}

val prepareNextDevIter by tasks.registering {
    mustRunAfter(handleRelease)
}

val releasedProjects = mutableListOf<Project>()
val createPullRequestNextDevIter by tasks.registering(CreatePullRequest::class) {
    user.set(ghReleaseDataProvider.map { it.user.get() })
    repo.set(ghReleaseDataProvider.map { it.repo.get() })
    branchName.set("bump-version")

    commitSummary.set("Prepare next dev iteration(s)")
    commitDescription.set(provider {
        "Update version and changelog for:\n" + releasedProjects.map {
            " - ${it.zapAddOn.addOnName.get()}"
        }.sorted().joinToString("\n")
    })

    dependsOn(prepareNextDevIter)
}

val releaseAddOn by tasks.registering

subprojects {
    if (parentProjects.contains(project.name)) {
        return@subprojects
    }

    apply(plugin = "eclipse")
    apply(plugin = "java-library")
    apply(plugin = "jacoco")
    apply(plugin = "org.zaproxy.add-on")

    val compileOnlyEclipse by configurations.creating {
        extendsFrom(configurations.get("compileOnly"))
    }

    eclipse {
        classpath {
            plusConfigurations.add(compileOnlyEclipse)
        }
    }

    java {
        // Compile with Java 8 when building ZAP releases.
        if (System.getenv("ZAP_RELEASE") != null) {
            toolchain {
                languageVersion.set(JavaLanguageVersion.of(8))
            }
        } else {
            sourceCompatibility = JavaVersion.VERSION_1_8
            targetCompatibility = JavaVersion.VERSION_1_8
        }
    }

    jacoco {
        toolVersion = jacocoToolVersion
    }

    tasks.named<JacocoReport>("jacocoTestReport") {
        reports {
            xml.isEnabled = true
        }
    }

    configurations {
        "compileClasspath" {
            exclude(group = "log4j")
            exclude(group = "org.apache.logging.log4j", module = "log4j-1.2-api")
        }
    }

    val apiGenClasspath = configurations.detachedConfiguration(dependencies.create("org.zaproxy:zap:2.10.0"))

    zapAddOn {
        releaseLink.set(project.provider { "https://github.com/zaproxy/zap-extensions/releases/${zapAddOn.addOnId.get()}-v@CURRENT_VERSION@" })

        manifest {
            changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
            repo.set("https://github.com/zaproxy/zap-extensions/")
        }

        apiClientGen {
            classpath.run {
                setFrom(apiGenClasspath)
                from(tasks.named(JavaPlugin.JAR_TASK_NAME))
            }
        }
    }

    val projectInfo = ProjectInfo.from(project)
    generateReleaseStateLastCommit {
        projects.add(projectInfo)
    }

    if (ReleaseState.read(projectInfo).isNewRelease()) {
        releasedProjects.add(project)

        val versionProvider = project.zapAddOn.addOnVersion
        val tagProvider = versionProvider.map { "${project.zapAddOn.addOnId.get()}-v$it" }
        val createReleaseAddOn by project.tasks.named<CreateTagAndGitHubRelease>("createRelease") {
            tag.set(tagProvider)
            val message = versionProvider.map { "${project.zapAddOn.addOnName.get()} version $it" }
            tagMessage.set(message)
            title.set(message)
        }
        releaseAddOn {
            dependsOn(createReleaseAddOn)

            dependsOn(handleRelease)
            dependsOn(createPullRequestNextDevIter)
        }

        val addOnRelease = AddOnRelease.from(project)
        addOnRelease.downloadUrl.set(addOnRelease.addOn.map { it.asFile.name }.map {
            "https://github.com/${ghReleaseDataProvider.get().repo.get()}/releases/download/${tagProvider.get()}/$it"
        })
        handleRelease {
            addOns.add(addOnRelease)

            mustRunAfter(createReleaseAddOn)
        }

        val prepareNextDevIterAddOn by project.tasks.named("prepareNextDevIter") {
            mustRunAfter(handleRelease)
        }
        prepareNextDevIter {
            dependsOn(prepareNextDevIterAddOn)
        }
    }
}

val createPullRequestRelease by tasks.registering(CreatePullRequest::class) {
    System.getenv("ADD_ON_IDS")?.let {
        val projects = it.split(Pattern.compile(" *, *")).map { name ->
            val project = subprojects.find { it.name == name }
            require(project != null) { "Add-on with project name $name not found." }
            project
        }

        projects.forEach {
            dependsOn(it.tasks.named("prepareRelease"))
        }

        user.set(ghReleaseDataProvider.map { it.user.get() })
        repo.set(ghReleaseDataProvider.map { it.repo.get() })
        branchName.set("release")

        commitSummary.set("Release add-on(s)")
        commitDescription.set(provider {
            "Release the following add-ons:\n" + projects.map {
                " - ${it.zapAddOn.addOnName.get()} version ${it.zapAddOn.addOnVersion.get()}"
            }.sorted().joinToString("\n")
        })
    }
}

tasks.register("reportMissingHelp") {
    description = "Reports the add-ons that do not have help pages."
    doLast {
        val addOns = mutableListOf<AddOnPluginExtension>()
        subprojects.forEach {
            it.plugins.withType(AddOnPlugin::class) {
                if (!File(it.projectDir, "src/main/javahelp").exists()) {
                    addOns.add(it.zapAddOn)
                }
            }
        }
        if (addOns.isEmpty()) {
            println("All add-ons have help.")
        } else {
            println("The following add-ons do not have help:")
            addOns.forEach { println("${it.addOnId.get()} (${it.addOnStatus.get().toString().toLowerCase(Locale.ROOT)})") }
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

fun Project.java(configure: JavaPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("java", configure)

fun Project.jacoco(configure: JacocoPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("jacoco", configure)

fun Project.zapAddOn(configure: AddOnPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("zapAddOn", configure)

val Project.zapAddOn: AddOnPluginExtension get() =
    (this as ExtensionAware).extensions.getByName("zapAddOn") as AddOnPluginExtension

val AddOnPluginExtension.gitHubRelease: GitHubReleaseExtension get() =
    (this as ExtensionAware).extensions.getByName("gitHubRelease") as GitHubReleaseExtension

fun AddOnPluginExtension.manifest(configure: ManifestExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("manifest", configure)

fun AddOnPluginExtension.apiClientGen(configure: ApiClientGenExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("apiClientGen", configure)

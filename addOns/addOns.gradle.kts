import me.champeau.gradle.japicmp.JapicmpTask
import org.cyclonedx.gradle.CycloneDxTask
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
import org.zaproxy.gradle.crowdin.CrowdinExtension

plugins {
    eclipse
    jacoco
    id("org.cyclonedx.bom") version "1.8.1" apply false
    id("org.rm3l.datanucleus-gradle-plugin") version "2.0.0" apply false
    id("org.zaproxy.add-on") version "0.10.0" apply false
    id("org.zaproxy.crowdin") version "0.4.0" apply false
    id("me.champeau.gradle.japicmp") version "0.4.2" apply false
}

description = "Common configuration of the add-ons."

val mandatoryAddOns = listOf(
    "callhome",
    "network",
)

val parentProjects = listOf(
    "webdrivers",
)

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
    commitDescription.set(
        provider {
            "Update version and changelog for:\n" + releasedProjects.map {
                " - ${it.zapAddOn.addOnName.get()}"
            }.sorted().joinToString("\n")
        },
    )

    dependsOn(prepareNextDevIter)
}

val releaseAddOn by tasks.registering
val allJarsForBom by tasks.registering {
    dependsOn(project(":testutils").tasks.named(JavaPlugin.JAR_TASK_NAME))
}

val crowdinExcludedProjects = setOf(
    childProjects.get("dev"),
)

subprojects {
    if (parentProjects.contains(project.name)) {
        return@subprojects
    }

    val useCrowdin = !crowdinExcludedProjects.contains(project)
    val mavenPublishAddOn = project.hasProperty("zap.maven.publish", "true")
    val japicmpAddOn = project.hasProperty("zap.japicmp", "true")

    apply(plugin = "eclipse")
    apply(plugin = "java-library")
    apply(plugin = "jacoco")
    apply(plugin = "org.cyclonedx.bom")
    apply(plugin = "org.rm3l.datanucleus-gradle-plugin")
    apply(plugin = "org.zaproxy.add-on")
    apply(plugin = "org.zaproxy.common")
    if (useCrowdin) {
        apply(plugin = "org.zaproxy.crowdin")
    }
    if (mavenPublishAddOn) {
        apply(plugin = "maven-publish")
        apply(plugin = "signing")
    }
    if (japicmpAddOn) {
        apply(plugin = "me.champeau.gradle.japicmp")
    }

    val compileOnlyEclipse by configurations.creating {
        extendsFrom(configurations.get("compileOnly"))
    }

    eclipse {
        classpath {
            plusConfigurations.add(compileOnlyEclipse)
        }
    }

    group = "org.zaproxy.addon"

    java {
        // Compile with appropriate Java version when building ZAP releases.
        if (System.getenv("ZAP_RELEASE") != null) {
            toolchain {
                languageVersion.set(JavaLanguageVersion.of(System.getenv("ZAP_JAVA_VERSION")))
            }
        }
    }

    tasks.named<JacocoReport>("jacocoTestReport") {
        reports {
            xml.required.set(true)
        }
    }

    configurations {
        "compileClasspath" {
            exclude(group = "log4j")
            exclude(group = "org.apache.logging.log4j", module = "log4j-1.2-api")
        }

        val zapAddOn by creating

        "compileOnly" {
            extendsFrom(zapAddOn)
        }

        "testImplementation" {
            extendsFrom(zapAddOn)
        }
    }

    val zapGav = "org.zaproxy:zap:2.15.0"
    dependencies {
        "zap"(zapGav)
    }

    val apiGenClasspath = configurations.detachedConfiguration(dependencies.create(zapGav))

    zapAddOn {
        releaseLink.set(project.provider { "https://github.com/zaproxy/zap-extensions/releases/${zapAddOn.addOnId.get()}-v@CURRENT_VERSION@" })

        manifest {
            zapVersion.set("2.15.0")

            changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
            repo.set("https://github.com/zaproxy/zap-extensions/")
        }

        apiClientGen {
            classpath.run {
                setFrom(apiGenClasspath)
                from(configurations.named(JavaPlugin.COMPILE_CLASSPATH_CONFIGURATION_NAME))
                from(tasks.named(JavaPlugin.JAR_TASK_NAME))
            }
        }
    }

    allJarsForBom {
        dependsOn(tasks.named(JavaPlugin.JAR_TASK_NAME))
    }

    val cyclonedxBom by tasks.existing(CycloneDxTask::class) {
        setDestination(layout.buildDirectory.dir("reports/bom-all").get().asFile)
        mustRunAfter(allJarsForBom)
    }

    val cyclonedxRuntimeBom by tasks.registering(CycloneDxTask::class) {
        setIncludeConfigs(listOf(JavaPlugin.RUNTIME_CLASSPATH_CONFIGURATION_NAME))
        setDestination(layout.buildDirectory.dir("reports/bom-runtime").get().asFile)
        setOutputFormat("json")
        mustRunAfter(allJarsForBom)
    }

    tasks.named<Jar>(AddOnPlugin.JAR_ZAP_ADD_ON_TASK_NAME) {
        from(cyclonedxRuntimeBom)
    }

    if (useCrowdin) {
        crowdin {
            credentials {
                token.set(System.getenv("CROWDIN_AUTH_TOKEN"))
            }

            configuration {
                file.set(file("$rootDir/gradle/crowdin.yml"))
                val addOnId = zapAddOn.addOnId.get()
                val resourcesPath = "org/zaproxy/zap/extension/$addOnId/resources/"
                tokens.set(
                    mutableMapOf(
                        "%addOnId%" to addOnId,
                        "%messagesPath%" to resourcesPath,
                        "%helpPath%" to resourcesPath,
                    ),
                )
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

            assets {
                register("bom") {
                    file.set(cyclonedxBom.map { project.layout.projectDirectory.file(File(it.destination.get(), "${it.outputName.get()}.json").absolutePath) })
                    contentType.set("application/json")
                }
            }
        }

        val crowdinUploadSourceFiles = if (useCrowdin) project.tasks.named("crowdinUploadSourceFiles") else null
        releaseAddOn {
            dependsOn(allJarsForBom)
            dependsOn(createReleaseAddOn)

            dependsOn(handleRelease)
            dependsOn(createPullRequestNextDevIter)

            if (useCrowdin) {
                dependsOn(crowdinUploadSourceFiles)
                if (crowdinUploadSourceFiles!!.isPresent) {
                    crowdinUploadSourceFiles {
                        mustRunAfter(createPullRequestNextDevIter)
                    }
                }
            }
        }

        val addOnRelease = AddOnRelease.from(project)
        addOnRelease.downloadUrl.set(
            addOnRelease.addOn.map { it.asFile.name }.map {
                "https://github.com/${ghReleaseDataProvider.get().repo.get()}/releases/download/${tagProvider.get()}/$it"
            },
        )
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

    if (mavenPublishAddOn) {
        val sourceSets = extensions.getByName("sourceSets") as SourceSetContainer

        tasks.register<Jar>("javadocJar") {
            from(tasks.named("javadoc"))
            archiveClassifier.set("javadoc")
        }

        tasks.register<Jar>("sourcesJar") {
            from(sourceSets.named("main").map { it.allJava })
            archiveClassifier.set("sources")
        }

        val ossrhUsername: String? by project
        val ossrhPassword: String? by project

        publishing {
            repositories {
                maven {
                    val releasesRepoUrl = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
                    val snapshotsRepoUrl = uri("https://oss.sonatype.org/content/repositories/snapshots/")
                    setUrl(provider { if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl })

                    if (ossrhUsername != null && ossrhPassword != null) {
                        credentials {
                            username = ossrhUsername
                            password = ossrhPassword
                        }
                    }
                }
            }

            publications {
                register<MavenPublication>("addon") {
                    from(components["java"])

                    artifact(tasks["sourcesJar"])
                    artifact(tasks["javadocJar"])

                    pom {
                        name.set(project.zapAddOn.addOnName.map { "ZAP - $it Add-on" })
                        packaging = "jar"
                        description.set(provider { project.description })
                        url.set("https://github.com/zaproxy/zap-extensions")
                        inceptionYear.set(project.property("zap.maven.pom.inceptionyear") as String)

                        organization {
                            name.set("ZAP")
                            url.set("https://www.zaproxy.org/")
                        }

                        mailingLists {
                            mailingList {
                                name.set("ZAP Developer Group")
                                post.set("zaproxy-develop@googlegroups.com")
                                archive.set("https://groups.google.com/group/zaproxy-develop")
                            }
                        }

                        scm {
                            url.set("https://github.com/zaproxy/zap-extensions")
                            connection.set("scm:git:https://github.com/zaproxy/zap-extensions.git")
                            developerConnection.set("scm:git:https://github.com/zaproxy/zap-extensions.git")
                        }

                        licenses {
                            license {
                                name.set("The Apache License, Version 2.0")
                                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                                distribution.set("repo")
                            }
                        }

                        developers {
                            developer {
                                id.set("AllAddOnDevs")
                                name.set("Everyone who has contributed to the add-on")
                                email.set("zaproxy-develop@googlegroups.com")
                            }
                        }
                    }
                }
            }
        }

        signing {
            if (project.hasProperty("signing.keyId")) {
                sign(publishing.publications["addon"])
            }
        }
    }

    if (japicmpAddOn) {
        val versionBC = project.property("zap.japicmp.baseversion") as String
        val japicmp by tasks.registering(JapicmpTask::class) {
            group = LifecycleBasePlugin.VERIFICATION_GROUP
            description = "Checks ${project.name}.jar binary compatibility with latest version ($versionBC)."

            oldClasspath.from(addOnJar(versionBC))
            newClasspath.from(tasks.named<Jar>(JavaPlugin.JAR_TASK_NAME))
            ignoreMissingClasses.set(true)

            richReport {
                destinationDir.set(layout.buildDirectory.dir("reports/japicmp/"))
                reportName.set("japi.html")
                addDefaultRules.set(true)
            }
        }

        tasks.named(LifecycleBasePlugin.CHECK_TASK_NAME) {
            dependsOn(japicmp)
        }
    }
}

val crowdinUploadSourceFiles by tasks.registering {
    System.getenv("ADD_ON_IDS")?.let {
        val projects = splitAddOnIds(it).map { name ->
            val project = subprojects.find { it.name == name }
            require(project != null) { "Add-on with project name $name not found." }

            project
        }.filter { !crowdinExcludedProjects.contains(it) }

        projects.forEach {
            dependsOn(it.tasks.named("crowdinUploadSourceFiles"))
        }
    }
}

val createPullRequestRelease by tasks.registering(CreatePullRequest::class) {
    System.getenv("ADD_ON_IDS")?.let {
        val projects = splitAddOnIds(it).map { name ->
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
        commitDescription.set(
            provider {
                "Release the following add-ons:\n" + projects.map {
                    " - ${it.zapAddOn.addOnName.get()} version ${it.zapAddOn.addOnVersion.get()}"
                }.sorted().joinToString("\n")
            },
        )
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
            addOns.forEach { println("${it.addOnId.get()} (${it.addOnStatus.get().toString().lowercase()})") }
        }
    }
}

tasks.register("copyMandatoryAddOns") {
    group = LifecycleBasePlugin.BUILD_GROUP
    description = "Copies the mandatory add-ons to zaproxy project."

    mandatoryProjects().forEach {
        dependsOn(it.tasks.named("copyZapAddOn"))
    }
}

tasks.register("deployMandatoryAddOns") {
    group = LifecycleBasePlugin.BUILD_GROUP
    description = "Deploys the mandatory add-ons to the ZAP home dir."

    mandatoryProjects().forEach {
        dependsOn(it.tasks.named("deployZapAddOn"))
    }
}

tasks.register<TestReport>("testReport") {
    destinationDirectory.set(layout.buildDirectory.dir("reports/allTests"))
    subprojects.forEach {
        it.plugins.withType(JavaPlugin::class) {
            testResults.from(it.tasks.withType<Test>())
        }
    }

    doLast {
        val reportUrl = File(destinationDirectory.get().getAsFile(), "index.html").toURI()
        logger.lifecycle("Test Report: $reportUrl")
    }
}

val jacocoReport by tasks.registering(JacocoReport::class) {
    subprojects.forEach {
        it.plugins.withType(JavaPlugin::class) {
            val sourceSets = it.extensions.getByName("sourceSets") as SourceSetContainer
            sourceDirectories.from(files(sourceSets["main"].java.srcDirs))
            classDirectories.from(files(sourceSets["main"].output.classesDirs))
            executionData(it.tasks.withType<Test>())
        }
    }

    doLast {
        val reportUrl = File(reports.html.outputLocation.get().getAsFile(), "index.html").toURI()
        logger.lifecycle("Coverage Report: $reportUrl")
    }
}

fun Project.java(configure: JavaPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("java", configure)

fun Project.jacoco(configure: JacocoPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("jacoco", configure)

fun Project.publishing(configure: PublishingExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("publishing", configure)

val Project.publishing: PublishingExtension get() =
    (this as ExtensionAware).extensions.getByName("publishing") as PublishingExtension

fun Project.signing(configure: SigningExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("signing", configure)

fun Project.zapAddOn(configure: AddOnPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("zapAddOn", configure)

val Project.zapAddOn: AddOnPluginExtension get() =
    (this as ExtensionAware).extensions.getByName("zapAddOn") as AddOnPluginExtension

val AddOnPluginExtension.gitHubRelease: GitHubReleaseExtension get() =
    (this as ExtensionAware).extensions.getByName("gitHubRelease") as GitHubReleaseExtension

fun Project.crowdin(configure: CrowdinExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("crowdin", configure)

val Project.crowdin: CrowdinExtension get() =
    (this as ExtensionAware).extensions.getByName("crowdin") as CrowdinExtension

fun AddOnPluginExtension.manifest(configure: ManifestExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("manifest", configure)

fun AddOnPluginExtension.apiClientGen(configure: ApiClientGenExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("apiClientGen", configure)

fun mandatoryProjects() =
    mandatoryAddOns.map { name ->
        val project = subprojects.find { it.name == name }
        require(project != null) { "Add-on with project name $name not found." }
        project
    }

fun Project.hasProperty(name: String, value: String) = hasProperty(name) && property(name) == value

fun Project.addOnJar(version: String): File {
    val oldGroup = group
    try {
        // https://discuss.gradle.org/t/is-the-default-configuration-leaking-into-independent-configurations/2088/6
        group = "virtual_group_for_japicmp"
        val conf = configurations.detachedConfiguration(dependencies.create("$oldGroup:$name:$version"))
        conf.isTransitive = false
        return conf.singleFile
    } finally {
        group = oldGroup
    }
}

fun splitAddOnIds(ids: String) = ids.split(",").map(String::trim)

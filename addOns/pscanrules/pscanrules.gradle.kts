import net.ltgt.gradle.errorprone.errorprone
import org.zaproxy.gradle.addon.AddOnStatus

description = "The release status Passive Scanner rules"

zapAddOn {
    addOnName.set("Passive scanner rules")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.40.0 & < 2.0.0")
                }

                // Not an actual dependency (yet) but allows to include passive scan add-on "by default".
                // Can be removed for the next main core release.
                register("pscan")
            }
        }

        extensions {
            register("org.zaproxy.zap.extension.pscanrules.payloader.ExtensionPayloader") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.pscanrules.payloader"))
                }
                dependencies {
                    addOns {
                        register("custompayloads") {
                            version.set(">= 0.9.0 & < 1.0.0")
                        }
                    }
                }
            }
        }
    }
}

plugins {
    antlr
}

configurations {
    api {
        setExtendsFrom(extendsFrom.filterNot { it == antlr.get() })
    }
}

dependencies {
    implementation(libs.pscanrules.re2j)
    implementation(libs.pscanrules.htmlunit.csp)

    antlr(libs.pscanrules.antlr)
    implementation(libs.pscanrules.antlr.runtime)

    zapAddOn("commonlib")
    zapAddOn("custompayloads")

    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/InfoPrivateAddressDisclosureScanRule.java",
            "src/**/InfoSessionIdUrlScanRule.java",
        ),
        listOf(
            "src/**/antlr/JavaScriptLexerBase.java",
        ),
    )
}

val knownVulnerabilitiesUpdater = "org.zaproxy.zap.extension.pscanrules.KnownVulnerabilitiesUpdater"
val knownVulnerabilitiesResources = "src/main/resources/org/zaproxy/zap/extension/pscanrules/resources"
val mainSourceSet = project.the<SourceSetContainer>()["main"]
val javaHelpDir = file("src/main/javahelp")
val generatedHelpDir = layout.buildDirectory.dir("generated/javahelp")

// The technologies checked by the ServerSideVersionScanRule: the ID accepted by the updater, the name used in
// the task names, the data file and the help page which lists its vulnerabilities.
data class KnownVulnerabilitiesTechnology(val id: String, val name: String, val source: String, val json: File, val page: String)

val knownVulnerabilitiesTechnologies =
    listOf(
        KnownVulnerabilitiesTechnology(
            "php",
            "Php",
            "the php-src security advisories",
            file("$knownVulnerabilitiesResources/php-known-vulnerabilities.json"),
            "php-known-vulnerabilities.html",
        ),
        KnownVulnerabilitiesTechnology(
            "apache",
            "Apache",
            "the Apache HTTP Server CVE records",
            file("$knownVulnerabilitiesResources/apache-known-vulnerabilities.json"),
            "apache-known-vulnerabilities.html",
        ),
    )

val updateKnownVulnerabilities by tasks.registering {
    group = "ZAP Misc"
    description = "Regenerates the known vulnerabilities files of all the technologies from their sources."
}

knownVulnerabilitiesTechnologies.forEach { tech ->
    val updateTask =
        tasks.register<JavaExec>("update${tech.name}KnownVulnerabilities") {
            group = "ZAP Misc"
            description = "Regenerates the ${tech.name} known vulnerabilities file from ${tech.source}."
            classpath = mainSourceSet.output + mainSourceSet.compileClasspath
            mainClass.set(knownVulnerabilitiesUpdater)
            args("update", tech.id, tech.json.path)
        }
    updateKnownVulnerabilities { dependsOn(updateTask) }
}

// The help pages, including the translated ones, contain just the surrounding text and tags which are
// replaced with the vulnerability details when the add-on is built.
val generateKnownVulnerabilitiesHelp by tasks.registering(JavaExec::class) {
    group = "build"
    description = "Fills in the known vulnerabilities help pages from the vulnerabilities files."
    classpath = mainSourceSet.output + mainSourceSet.compileClasspath
    mainClass.set(knownVulnerabilitiesUpdater)
    inputs.files(knownVulnerabilitiesTechnologies.map { it.json })
    inputs.file(file("$knownVulnerabilitiesResources/known-vulnerabilities-help-entry-template.html"))
    inputs.files(fileTree(javaHelpDir) { include(knownVulnerabilitiesTechnologies.map { "**/${it.page}" }) })
    outputs.dir(generatedHelpDir)
    doFirst { delete(generatedHelpDir) }
    args("help", javaHelpDir.path, generatedHelpDir.get().asFile.path)
    knownVulnerabilitiesTechnologies.forEach { args(it.json.path, it.page) }
}

// The JavaHelp indexer strips a single directory prefix, that of the helpset, from the indexed paths, so the
// generated pages are indexed from a merged copy of the help directory rather than from a second source root.
val mergedHelpDir = layout.buildDirectory.dir("merged/javahelp")
val mergeKnownVulnerabilitiesHelp by tasks.registering(Sync::class) {
    description = "Merges the help directory and the generated help pages, for indexing."
    from(javaHelpDir) { exclude(knownVulnerabilitiesTechnologies.map { "**/${it.page}" }) }
    from(generatedHelpDir)
    into(mergedHelpDir)
    dependsOn(generateKnownVulnerabilitiesHelp)
}

tasks.withType<org.zaproxy.gradle.addon.jh.tasks.JavaHelpIndexer>().configureEach {
    val helpsetPath = javaHelpDir.toPath().relativize(helpset.get().asFile.toPath())
    helpset.set(mergedHelpDir.map { it.file(helpsetPath.toString()) })
    setSource(mergedHelpDir.map { it.dir(helpsetPath.parent.toString()) })
    dependsOn(mergeKnownVulnerabilitiesHelp)
}

tasks.named<Jar>("jarZapAddOn") {
    val pages = knownVulnerabilitiesTechnologies.map { it.page }
    exclude { it.name in pages && it.file.toPath().startsWith(javaHelpDir.toPath()) }
    from(generatedHelpDir)
    dependsOn(generateKnownVulnerabilitiesHelp)
}

val jsLexerPkg = "org.zaproxy.zap.extension.pscanrules.antlr"
val jsLexerDir = jsLexerPkg.replace('.', '/')
val generateGrammarSource by tasks.existing(AntlrTask::class) {
    val libDir = "$outputDirectory/$jsLexerDir"
    arguments = arguments + listOf("-package", jsLexerPkg, "-lib", libDir)

    doFirst {
        mkdir(libDir)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.errorprone.excludedPaths.set(".*/(generated-src|$jsLexerDir)/.*")
}

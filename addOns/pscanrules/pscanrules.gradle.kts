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
val phpKnownVulnerabilitiesJson = file("src/main/resources/org/zaproxy/zap/extension/pscanrules/resources/php-known-vulnerabilities.json")
val phpKnownVulnerabilitiesPage = "php-known-vulnerabilities.html"
val mainSourceSet = project.the<SourceSetContainer>()["main"]
val javaHelpDir = file("src/main/javahelp")
val generatedHelpDir = layout.buildDirectory.dir("generated/javahelp")

tasks.register<JavaExec>("updatePhpKnownVulnerabilities") {
    group = "ZAP Misc"
    description = "Regenerates the PHP known vulnerabilities file from the php-src security advisories."
    classpath = mainSourceSet.output + mainSourceSet.compileClasspath
    mainClass.set(knownVulnerabilitiesUpdater)
    args("update", phpKnownVulnerabilitiesJson.path)
}

// The help pages, including the translated ones, contain just the surrounding text and tags which are
// replaced with the vulnerability details when the add-on is built.
val generatePhpKnownVulnerabilitiesHelp by tasks.registering(JavaExec::class) {
    group = "build"
    description = "Fills in the PHP known vulnerabilities help pages from the vulnerabilities file."
    classpath = mainSourceSet.output + mainSourceSet.compileClasspath
    mainClass.set(knownVulnerabilitiesUpdater)
    inputs.file(phpKnownVulnerabilitiesJson)
    inputs.file(file("src/main/resources/org/zaproxy/zap/extension/pscanrules/resources/known-vulnerabilities-help-entry-template.html"))
    inputs.files(fileTree(javaHelpDir) { include("**/$phpKnownVulnerabilitiesPage") })
    outputs.dir(generatedHelpDir)
    doFirst { delete(generatedHelpDir) }
    args(
        "help",
        phpKnownVulnerabilitiesJson.path,
        phpKnownVulnerabilitiesPage,
        javaHelpDir.path,
        generatedHelpDir.get().asFile.path,
    )
}

// The JavaHelp indexer strips a single directory prefix, that of the helpset, from the indexed paths, so the
// generated pages are indexed from a merged copy of the help directory rather than from a second source root.
val mergedHelpDir = layout.buildDirectory.dir("merged/javahelp")
val mergePhpKnownVulnerabilitiesHelp by tasks.registering(Sync::class) {
    description = "Merges the help directory and the generated help pages, for indexing."
    from(javaHelpDir) { exclude("**/$phpKnownVulnerabilitiesPage") }
    from(generatedHelpDir)
    into(mergedHelpDir)
    dependsOn(generatePhpKnownVulnerabilitiesHelp)
}

tasks.withType<org.zaproxy.gradle.addon.jh.tasks.JavaHelpIndexer>().configureEach {
    val helpsetPath = javaHelpDir.toPath().relativize(helpset.get().asFile.toPath())
    helpset.set(mergedHelpDir.map { it.file(helpsetPath.toString()) })
    setSource(mergedHelpDir.map { it.dir(helpsetPath.parent.toString()) })
    dependsOn(mergePhpKnownVulnerabilitiesHelp)
}

tasks.named<Jar>("jarZapAddOn") {
    exclude { it.name == phpKnownVulnerabilitiesPage && it.file.toPath().startsWith(javaHelpDir.toPath()) }
    from(generatedHelpDir)
    dependsOn(generatePhpKnownVulnerabilitiesHelp)
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

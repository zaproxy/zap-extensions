import net.ltgt.gradle.errorprone.errorprone
import org.zaproxy.gradle.addon.AddOnStatus

description = "A common library, for use by other add-ons."

plugins {
    antlr
}

zapAddOn {
    addOnName.set("Common Library")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/common-library/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        file.set(file("$projectDir/gradle/crowdin.yml"))
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    api(platform("com.fasterxml.jackson:jackson-bom:2.19.1"))
    api("com.fasterxml.jackson.core:jackson-databind")
    api("com.fasterxml.jackson.dataformat:jackson-dataformat-xml")
    api("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jdk8")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")

    val antlrVersion = "4.13.0"
    antlr("org.antlr:antlr4:$antlrVersion")
    implementation("org.antlr:antlr4-runtime:$antlrVersion")

    implementation("commons-io:commons-io:2.16.1")
    implementation("org.apache.commons:commons-csv:1.10.0")
    implementation("org.apache.commons:commons-collections4:4.4")

    testImplementation(project(":testutils"))
}

val jsParserPkg = "org.zaproxy.addon.commonlib.parserapi.impl"
val jsParserDir = jsParserPkg.replace('.', '/')
val generateGrammarSource by tasks.existing(AntlrTask::class) {
    val libDir = "$outputDirectory/$jsParserDir"
    arguments = arguments + listOf("-package", jsParserPkg, "-lib", libDir)

    doFirst {
        mkdir(libDir)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.errorprone.excludedPaths.set(".*/(generated-src|$jsParserDir)/.*")
}

tasks.named("generateGrammarSource") {
    mustRunAfter(tasks.named("generateEffectiveLombokConfig"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf("src/**/$jsParserDir/*.java"),
    )
}

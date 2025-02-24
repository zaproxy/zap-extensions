import net.ltgt.gradle.errorprone.errorprone
import org.zaproxy.gradle.spotless.ValidateImports

plugins {
    id("com.diffplug.spotless")
    id("org.zaproxy.common") version "0.3.0" apply false
    id("com.github.ben-manes.versions") version "0.50.0"
    id("org.sonarqube") version "4.3.0.3225"
    id("net.ltgt.errorprone") version "3.1.0"
    id("io.freefair.lombok") version "8.10.2"
}

apply(from = "$rootDir/gradle/ci.gradle.kts")

val validateImports =
    ValidateImports(
        mapOf(
            "import org.apache.commons.lang." to
                "Import/use classes from Commons Lang 3, instead of Lang 2.",
        ),
    )

allprojects {
    apply(plugin = "com.diffplug.spotless")
    apply(plugin = "com.github.ben-manes.versions")
    apply(plugin = "net.ltgt.errorprone")
    apply(plugin = "io.freefair.lombok")

    repositories {
        mavenCentral()
    }

    spotless {
        kotlinGradle {
            ktlint()
        }

        project.plugins.withType(JavaPlugin::class) {
            java {
                bumpThisNumberIfACustomStepChanges(1)
                custom("validateImports", validateImports)
            }
        }
    }

    project.plugins.withType(JavaPlugin::class) {
        dependencies {
            "errorprone"("com.google.errorprone:error_prone_core:2.26.1")

            // Include annotations used by Log4j2 Core library to avoid compiler warnings.
            "compileOnly"("biz.aQute.bnd:biz.aQute.bnd.annotation:6.4.1")
            "compileOnly"("com.google.code.findbugs:findbugs-annotations:3.0.1")
            "testCompileOnly"("biz.aQute.bnd:biz.aQute.bnd.annotation:6.4.1")
            "testCompileOnly"("com.google.code.findbugs:findbugs-annotations:3.0.1")
        }

        java {
            val javaVersion = JavaVersion.VERSION_17
            sourceCompatibility = javaVersion
            targetCompatibility = javaVersion
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        if (JavaVersion.current().getMajorVersion() >= "21") {
            options.compilerArgs = options.compilerArgs + "-Xlint:-this-escape"
        }
        options.errorprone {
            disableAllChecks.set(true)
            error(
                "MissingOverride",
                "WildcardImport",
            )
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
}

sonarqube {
    properties {
        property("sonar.projectKey", "zaproxy_zap-extensions")
        property("sonar.organization", "zaproxy")
        property("sonar.host.url", "https://sonarcloud.io")
        // Workaround https://sonarsource.atlassian.net/browse/SONARGRADL-126
        property("sonar.exclusions", "**/*.gradle.kts")
    }
}

fun Project.java(configure: JavaPluginExtension.() -> Unit): Unit = (this as ExtensionAware).extensions.configure("java", configure)

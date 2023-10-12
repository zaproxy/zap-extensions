import net.ltgt.gradle.errorprone.errorprone

plugins {
    id("com.diffplug.spotless")
    id("com.github.ben-manes.versions") version "0.47.0"
    id("org.sonarqube") version "4.3.0.3225"
    id("net.ltgt.errorprone") version "3.1.0"
}

apply(from = "$rootDir/gradle/ci.gradle.kts")

allprojects {
    apply(plugin = "com.diffplug.spotless")
    apply(plugin = "com.github.ben-manes.versions")
    apply(plugin = "net.ltgt.errorprone")

    repositories {
        mavenCentral()
    }

    spotless {
        kotlinGradle {
            ktlint()
        }

        project.plugins.withType(JavaPlugin::class) {
            java {
                licenseHeaderFile("$rootDir/gradle/spotless/license.java")
                googleJavaFormatAosp()
            }
        }
    }

    project.plugins.withType(JavaPlugin::class) {
        dependencies {
            "errorprone"("com.google.errorprone:error_prone_core:2.20.0")
        }

        java {
            val javaVersion = JavaVersion.VERSION_11
            sourceCompatibility = javaVersion
            targetCompatibility = javaVersion
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "utf-8"
        options.compilerArgs = listOf("-Xlint:all", "-Xlint:-path", "-Xlint:-options", "-Werror")
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

fun Project.java(configure: JavaPluginExtension.() -> Unit): Unit =
    (this as ExtensionAware).extensions.configure("java", configure)

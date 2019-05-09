plugins {
    id("com.diffplug.gradle.spotless")
}

apply(from = "$rootDir/gradle/travis-ci.gradle.kts")
apply(from = "$rootDir/gradle/lgtm.gradle.kts")

allprojects {
    apply(plugin = "com.diffplug.gradle.spotless")

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
                googleJavaFormatAosp(project)
            }
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "utf-8"
        options.compilerArgs = listOf("-Xlint:all", "-Xlint:-path", "-Xlint:-options", "-Werror")
    }
}
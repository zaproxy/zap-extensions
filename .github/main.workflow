workflow "Release Add-On" {
  on = "push"
  resolves = ["Build and Release Add-On"]
}

action "Add-On Tag Filter" {
  uses = "actions/bin/filter@3c0b4f0e63ea54ea5df2914b4fabf383368cd0da"
  args = "tag *-v*"
}

action "Actor Filter" {
  uses = "actions/bin/filter@3c0b4f0e63ea54ea5df2914b4fabf383368cd0da"
  args = ["actor", "kingthorin", "psiinon", "thc202"]
}

action "Build and Release Add-On" {
  uses = "docker://openjdk:8"
  needs = ["Actor Filter", "Add-On Tag Filter"]
  runs = "./gradlew"
  args = "createReleaseFromGitHubRef"
  secrets = ["GITHUB_TOKEN"]
}
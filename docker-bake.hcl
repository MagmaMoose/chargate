# Container build for the Chargate token-broker service. The release workflow
# (Diatreme) auto-detects this file and builds + pushes ghcr.io/magmamoose/chargate
# (pr-<N> on PRs, the release version + floating major on push to main).
variable "VERSION" { default = "latest" }
variable "REGISTRY" { default = "ghcr.io" }
variable "IMAGE_NAME" { default = "magmamoose/chargate" }
variable "PLATFORMS" { default = "linux/amd64,linux/arm64" }

group "default" {
  targets = ["app"]
}

target "app" {
  context    = "."
  dockerfile = "broker/Dockerfile"
  platforms  = split(",", PLATFORMS)
  tags       = ["${REGISTRY}/${IMAGE_NAME}:${VERSION}"]
}

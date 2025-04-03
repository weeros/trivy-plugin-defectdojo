# trivy-plugin-template
Template for Trivy plugins

**NOTE: Replace <org_name>, trivy-plugin-defectdojo and <plugin_name> in go.mod, goreleaser.yaml and plugin.yaml with the appropriate values.**

## Installation
```shell
trivy plugin install github.com/weeros/trivy-plugin-defectdojo
```

## Usage

```shell
trivy image --format json --output plugin=<plugin_name> [--output-plugin-arg plugin_flags] <image_name>
```

OR

```shell
trivy image -f json <image_name> | trivy <plugin_name> [plugin_flags]
```
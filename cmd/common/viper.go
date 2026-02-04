package common

import (
	"fmt"
	"os"
)

//goland:noinspection GoCommentStart
const (
	VEnvPrefix         = "TRIVY_PLUGIN_DEFECTDOJO"
	VDefaultConfigName = ".trivy_plugin_defectdojo"

	// Root config keys

	VConfig        = "config"
	VConfigLong    = "config"
	VConfigShort   = "c"
	VConfigDefault = ""
	VConfigUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_CONFIG
Optional config file (default $HOME/.trivy_plugin_defectdojo.yaml)`

	VLogLevel        = "log-level"
	VLogLevelLong    = "log-level"
	VLogLevelShort   = "l"
	VLogLevelDefault = "info"
	VLogLevelUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_LOG_LEVEL
CfgFile: log-level
Log level [debug, info, warn, error]`

	VLogFormat        = "log-format"
	VLogFormatLong    = "log-format"
	VLogFormatDefault = "console"
	VLogFormatUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_LOG_FORMAT
CfgFile: log-format
Log format [console, json, dev, none]`

	VNoColor        = "no-color"
	VNoColorLong    = "no-color"
	VNoColorDefault = false
	VNoColorUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_NO_COLOR
CfgFile: no-color
Disable colorized output`

	VUrlApi        = "url-api"
	VUrlApiLong    = "url-api"
	VUrlApiDefault = "http://localhost:8081"
	VUrlApiUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_URL_API
CfgFile: url-api
Defectdojo URL`

	VApiKey        = "apikey"
	VApiKeyLong    = "apikey"
	VApiKeyDefault = ""
	VApiKeyUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_APIKEY
CfgFile: apikey
Defectdojo API Key`

	VProductID        = "product-id"
	VProductIDLong    = "product-id"
	VProductIDDefault = 0
	VProductIDUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_PRODUCT_ID
CfgFile: product-id
Defectdojo Product ID`

	VProductName        = "product-name"
	VProductNameLong    = "product-name"
	VProductNameDefault = ""
	VProductNameUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_PRODUCT_NAME
CfgFile: product-name
Defectdojo Product Name`

	VProductTypeID        = "product-type-id"
	VProductTypeIDLong    = "product-type-id"
	VProductTypeIDDefault = 0
	VProductTypeIDUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_PRODUCT_TYPE_ID
CfgFile: product-type-id
Defectdojo Product Type ID`

	VproductTypeName        = "product-type-name"
	VproductTypeNameLong    = "product-type-name"
	VproductTypeNameDefault = "internal"
	VproductTypeNameUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_PRODUCT_TYPE_NAME
CfgFile: product-type-name
Defectdojo Product Type Name`


	VEngagementID        = "engagement-id"
	VEngagementIDLong    = "engagement-id"
	VEngagementIDDefault = 0
	VEngagementIDUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_ENGAGEMENT_ID
CfgFile: engagement-id
Defectdojo Engagement ID`


	VEngagementName        = "engagement-name"
	VEngagementNameLong    = "engagement-name"
	VEngagementNameDefault = "build"
	VEngagementNameUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_ENGAGEMENT_NAME
CfgFile: engagement-name
Defectdojo Engagement Name`

	VEngagementBuildID        = "engagement-build-id"
	VEngagementBuildIDLong    = "engagement-build-id"
	VEngagementBuildIDDefault = ""
	VEngagementBuildIDUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_ENGAGEMENT_BUILD_ID
CfgFile: engagement-build-id
Defectdojo Engagement Build ID`

	VEngagementSourceCodeURI        = "engagement-source-code-uri"
	VEngagementSourceCodeURILong    = "engagement-source-code-uri"
	VEngagementSourceCodeURIDefault = true
	VEngagementSourceCodeURIUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_ENGAGEMENT_SROURCE_CODE_URI
CfgFile: engagement-source-code-uri
Defectdojo Engagement Source Code URI`

	VEngagementDeduplication        = "engagement-deduplication"
	VEngagementDeduplicationLong    = "engagement-deduplication"
	VEngagementDeduplicationDefault = true
	VEngagementDeduplicationUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_ENGAGEMENT_DEDUPLICATION
CfgFile: engagement-deduplication
Defectdojo Engagement Deduplication`


	VEngagementTags		= "engagement-tags"
	VEngagementTagsLong	= "engagement-tags"
	VEngagementTagsDefault = ""
	VEngagementTagsUsage	= `Env: TRIVY_PLUGIN_DEFECTDOJO_ENGAGEMENT_TAGS
CfgFile: engagement-tags
Defectdojo Engagement Tags (comma separated)`

	VImportBranchTag        = "import-branch-tag"
	VImportBranchTagLong    = "import-branch-tag"
	VImportBranchTagDefault = ""
	VImportBranchTagUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_IMPORT_BRANCH_TAG
CfgFile: import-branch-tag
Branch or tag name to associate with the imported scan`

	VImportTags        = "import-tags"
	VImportTagsLong    = "import-tags"
	VImportTagsDefault = ""
	VImportTagsUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_IMPORT_TAGS
CfgFile: import-tags
Additional tags (comma separated) to associate with the imported scan`

	VImportCommitHash        = "import-commit-hash"
	VImportCommitHashLong    = "import-commit-hash"
	VImportCommitHashDefault = ""
	VImportCommitHashUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_IMPORT_COMMIT_HASH
CfgFile: import-commit-hash
Commit hash to associate with the imported scan`

	VImportBuildID        = "import-build-id"
	VImportBuildIDLong    = "import-build-id"
	VImportBuildIDDefault = ""
	VImportBuildIDUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_IMPORT_BUILD_ID
CfgFile: import-build-id
Build ID to associate with the imported scan`
	
	VImportReportJSON        = "import-report-json"	
	VImportReportJSONLong    = "import-report-json"
	VImportReportJSONDefault = "trivy.report.json"
	VImportReportJSONUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_IMPORT_REPORT_JSON
CfgFile: import-report-json
Path to the JSON report to import`

	VImportAutoCreate        = "import-auto-create"
	VImportAutoCreateLong    = "import-auto-create"
	VImportAutoCreateDefault = false
	VImportAutoCreateUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_IMPORT_AUTO_CREATE
CfgFile: import-auto-create
Automatically create missing entities (product, engagement) during import`

	VModeReImport        = "mode-reimport"
	VModeReImportLong    = "mode-reimport"
	VModeReImportDefault = false
	VModeReImportUsage   = `Env: TRIVY_PLUGIN_DEFECTDOJO_MODE_REIMPORT
CfgFile: mode-reimport
Use re-import mode to update existing scan findings`
)

func ValidateConfig(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("config path cannot be empty")
	}
	// Check if the file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", configPath)
	}

	return nil
}

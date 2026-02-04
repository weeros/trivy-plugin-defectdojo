// importscan demonstrates the process of uploading a scan report into DefectDojo.
// Details of the import are defined by an ImportScan struct.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/weeros/trivy-plugin-defectdojo/cmd/common"
	"github.com/weeros/trivy-plugin-defectdojo/pkg/logger"

	"github.com/truemilk/go-defectdojo/defectdojo"
)






func NewUploadCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "upload [flags]",
		Short:         "Upload a sbom to DependencyTrack",
		SilenceUsage:  false,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			urlApi := viper.GetString(common.VUrlApi)
			apikey := viper.GetString(common.VApiKey)

			ProductId := viper.GetInt(common.VProductID)
			ProductName := viper.GetString(common.VProductName)
			EngagementId := viper.GetInt(common.VEngagementID)
			EngagementName := viper.GetString(common.VEngagementName)
			
			if(ProductId == 0 && len(ProductName) == 0 || EngagementId ==0 && len(EngagementName) == 0 ) { 
				fmt.Println("TRIVY_DEFECTDOJO_PRODUCT_ID or TRIVY_DEFECTDOJO_PRODUCT_NAME is set", ProductName)
				return nil
			}

			err := upload(urlApi, apikey, ProductName, EngagementName)
			if err != nil {
				logger.Default().Error("Error during uploading sbom", "error", err)
				return err
			}
			return nil
		},
		Example: `
# Upload a local dependencytrack sbom:
trivy dependencytrack upload --url-api http://dependencytrack.local:8081 --apikey <API_KEY> --project-name my-project --project-version 1.0.0 --bom-file ./sbom.json

export TRIVY_PLUGIN_DEPENDENCYTRACK_URL=http://localhost:8081
export TRIVY_PLUGIN_DEPENDENCYTRACK_APIKEY=<API_KEY>
trivy dependencytrack upload 
`,
	}

	cmd.Flags().String(common.VUrlApi, common.VUrlApiDefault, common.VUrlApiUsage)
	err := viper.BindPFlag(common.VUrlApi, cmd.Flags().Lookup(common.VUrlApiLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}

	cmd.Flags().String(common.VApiKey, common.VApiKeyDefault, common.VApiKeyUsage)
	err = viper.BindPFlag(common.VApiKey, cmd.Flags().Lookup(common.VApiKeyLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}


	cmd.Flags().String(common.VProductName, common.VProductNameDefault, common.VProductNameUsage)
	err = viper.BindPFlag(common.VProductName, cmd.Flags().Lookup(common.VProductNameLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}

	cmd.Flags().String(common.VEngagementName, common.VEngagementNameDefault, common.VEngagementNameUsage)
	err = viper.BindPFlag(common.VEngagementName, cmd.Flags().Lookup(common.VEngagementNameLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}


	return cmd
}
















func upload(urlApi string, apikey string, productName string, engagementName string) error {
    
	client := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	dj, err := defectdojo.NewDojoClient(urlApi, apikey, client)
	if err != nil {
		return err
	}

	ctx := context.Background()


	manageProduct(ctx,dj)
	manageEngagement(ctx,dj)
	if viper.GetBool(common.VModeReImport) {
		manageReImportScan(ctx,dj)	
	} else {
		manageImportScan(ctx,dj)	
	}

	return nil
}



func manageProduct(ctx context.Context, dj *defectdojo.Client) {
	
	if(viper.GetInt(common.VProductID) == 0) {
		opts := &defectdojo.ProductsOptions{
			Limit:    1,
			Name: url.QueryEscape(viper.GetString(common.VProductName)),
		}
	
		resp, err := dj.Products.List(ctx, opts)
		if err != nil {
			fmt.Println("product:list:", err)
			return
		}
	
		products := *resp.Results
		if( *resp.Count > 0) {
			viper.Set(common.VProductID, *products[0].ID)
		} 
	}

	if(viper.GetInt(common.VProductID) == 0) {
					
		if(viper.GetInt(common.VProductTypeID) == 0) {
				
			opts := &defectdojo.ProductTypesOptions{
				Name: url.QueryEscape(viper.GetString(common.VproductTypeName)),
			}

			resp, err := dj.ProductTypes.List(ctx, opts)
			if err != nil {
				fmt.Println("ProductType:", err)
				return
			}
		
			productTypes := *resp.Results
			if( *resp.Count > 0) {
				viper.Set(common.VProductTypeID, *productTypes[0].Id)
			}

		} else {
			_, err := dj.ProductTypes.Read(ctx, viper.GetInt(common.VProductTypeID))
			if err != nil {
				fmt.Println("ProductType:", err)
				return
			}
		}
		
		
		if(viper.GetInt(common.VProductTypeID) == 0) {
		
			VproductTypeName := viper.GetString(common.VproductTypeName)
			productType := &defectdojo.ProductType{
				Name: &VproductTypeName,
			}

			resp, err := dj.ProductTypes.Create(ctx, productType)
			if err != nil {
				fmt.Println("ProductType:", err)
				return
			}
			fmt.Println("ProductType created !")			
			viper.Set(common.VProductTypeID, *resp.Id)
		}

		productName := viper.GetString(common.VProductName)
		productTypeID := viper.GetInt(common.VProductTypeID)
		product := &defectdojo.Product{
			Name: &productName,
			ProdType: &productTypeID,
			Description: defectdojo.Str("Change Me !"),
		}

		resp, err := dj.Products.Create(ctx, product)
		if err != nil {
			fmt.Println("Product:", err)
			return
		}
		fmt.Println("Product created !")			
		viper.Set(common.VProductID, *resp.ID)
	}


	product, err := dj.Products.Read(ctx, viper.GetInt(common.VProductID))
	if err != nil {
		fmt.Println("product:read:", err)
		return
	}

	fmt.Println("Product:", string(*product.Name))
}

func manageEngagement(ctx context.Context, dj *defectdojo.Client) {

	if(viper.GetInt(common.VEngagementID) > 0) {
		_, err := dj.Engagements.Read(ctx, viper.GetInt(common.VEngagementID))
		if err != nil {
			fmt.Println("Engagement:", err)
			viper.Set(common.VEngagementID, 0)
		}
	}

	if(viper.GetInt(common.VEngagementID) == 0) {
		opts2 := &defectdojo.EngagementsOptions{
			Limit:    1,
			Name: url.QueryEscape(viper.GetString(common.VEngagementName)),
			Product: viper.GetInt(common.VProductID),
		}

		resp, err := dj.Engagements.List(ctx, opts2)
		if err != nil {
			fmt.Println("Engagement:", err)
			return
		}
	
		engagements := *resp.Results
		if( *resp.Count > 0) {
			viper.Set(common.VEngagementID, *engagements[0].Id)
		}
	} 

	if(viper.GetInt(common.VEngagementID) == 0) {
		targetStart := time.Now()
		targetEnd := targetStart.AddDate(1, 0, 0)
		
		targetStartFormatted := fmt.Sprintf("%d-%02d-%02d", targetStart.Year(), targetStart.Month(), targetStart.Day())
		targetEndFormatted := fmt.Sprintf("%d-%02d-%02d", targetEnd.Year(), targetEnd.Month(), targetEnd.Day())

		arr := strings.FieldsFunc(viper.GetString(common.VEngagementTags), func(r rune) bool {
		   return r == ','
		})
VEngagementName:=viper.GetString(common.VEngagementName)
VProductID:=viper.GetInt(common.VProductID)
		engagement := &defectdojo.Engagement{
			Name: &VEngagementName,
			Product: &VProductID,
			Tags: defectdojo.Slice(arr),
			TargetStart: defectdojo.Str(targetStartFormatted),
			TargetEnd: defectdojo.Str(targetEndFormatted),
			SourceCodeManagementUri: defectdojo.Str(viper.GetString(common.VEngagementSourceCodeURI)),
			EngagementType: defectdojo.Str("CI/CD"),
			DeduplicationOnEngagement: defectdojo.Bool(viper.GetBool(common.VEngagementDeduplication)),
		}

		resp, err := dj.Engagements.Create(ctx, engagement)
		if err != nil {
			fmt.Println("Engagement:", err)
			return
		}
		fmt.Println("Engagement created !")			
		viper.Set(common.VEngagementID, *resp.Id)
	} 

	engagement, err := dj.Engagements.Read(ctx, viper.GetInt(common.VEngagementID))
	if err != nil {
		fmt.Println("Engagement:", err)
		return
	}
	b, err := json.Marshal(engagement)
	if err != nil {
		fmt.Println("Engagement:marshal:", err)
		return
	}
	fmt.Println("Engagement:", string(*engagement.Name))
	fmt.Println(string(b))
}

func manageImportScan(ctx context.Context, dj *defectdojo.Client) {

	arr := strings.FieldsFunc(viper.GetString(common.VImportTags), func(r rune) bool {
		return r == ' '
	 })

	scan := &defectdojo.ImportScan{
		ProductId:         defectdojo.Int(viper.GetInt(common.VProductID)),
		Engagement:        defectdojo.Int(viper.GetInt(common.VEngagementID)),
		ScanType:          defectdojo.Str("Trivy Scan"),
		BranchTag:         defectdojo.Str(viper.GetString(common.VImportBranchTag)),
		CommitHash:        defectdojo.Str(viper.GetString(common.VImportCommitHash)),
		BuildId:           defectdojo.Str(viper.GetString(common.VImportBuildID)),
		Tags:              defectdojo.Slice(arr),
		File:              defectdojo.Str(viper.GetString(common.VImportReportJSON)),
		AutoCreateContext: defectdojo.Bool(viper.GetBool(common.VImportAutoCreate)),
	}	

	resp1, err := dj.ImportScan.Create(ctx, scan)
	if err != nil {
		fmt.Println("ImportScan:", err)
		return
	}
	
	b, err := json.Marshal(resp1)
	if err != nil {
		fmt.Println("ImportScan:", err)
		return
	}

	fmt.Println("ImportScan:",string(viper.GetString(common.VImportReportJSON)))
	fmt.Println(string(b))
}

func manageReImportScan(ctx context.Context, dj *defectdojo.Client) {

	arr := strings.FieldsFunc(viper.GetString(common.VImportTags), func(r rune) bool {
		return r == ' '
	 })

	scan := &defectdojo.ReImportScan{
		ProductId:         defectdojo.Int(viper.GetInt(common.VProductID)),
		EngagementId:        defectdojo.Int(viper.GetInt(common.VEngagementID)),
		ScanType:          defectdojo.Str("Trivy Scan"),
		TestTitle:         defectdojo.Str("Trivy Scan"),
		BranchTag:         defectdojo.Str(viper.GetString(common.VImportBranchTag)),
		CommitHash:        defectdojo.Str(viper.GetString(common.VImportCommitHash)),
		BuildId:           defectdojo.Str(viper.GetString(common.VImportBuildID)),
		Tags:              defectdojo.Slice(arr),
		File:              defectdojo.Str(viper.GetString(common.VImportReportJSON)),
		AutoCreateContext: defectdojo.Bool(viper.GetBool(common.VImportAutoCreate)),
	}
	
	resp1, err := dj.ReImportScan.Create(ctx, scan)
	if err != nil {
		fmt.Println("ReImportScan:", err)
		return
	}
	
	b, err := json.Marshal(resp1)
	if err != nil {
		fmt.Println("ReImportScan:", err)
		return
	}

	fmt.Println("ReImportScan:",string(viper.GetString(common.VImportReportJSON)))
	fmt.Println(string(b))
}
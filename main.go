// importscan demonstrates the process of uploading a scan report into DefectDojo.
//
// Details of the import are defined by an ImportScan struct.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/truemilk/go-defectdojo/defectdojo"
)

type Config struct {
    URL    string `env:"TRIVY_DEFECTDOJO_URI" localhost:"8080"`
    APIKEY   string `env:"TRIVY_DEFECTDOJO_APIKEY" envDefault:"xxxxxxxxx"`
    PRODUCT_ID   int `env:"TRIVY_DEFECTDOJO_PRODUCT_ID" envDefault:"0"`
    PRODUCT_NAME  string `env:"TRIVY_DEFECTDOJO_PRODUCT_NAME" envDefault:""`
    PRODUCT_TYPE_ID   int `env:"TRIVY_DEFECTDOJO_PRODUCT_TYPE_ID" envDefault:"0"`
    PRODUCT_TYPE_NAME  string `env:"TRIVY_DEFECTDOJO_PRODUCT_TYPE_NAME" envDefault:"internal"`
    ENGAGEMENT_ID   int `env:"TRIVY_DEFECTDOJO_ENGAGEMENT_ID" envDefault:"0"`
    ENGAGEMENT_NAME  string `env:"TRIVY_DEFECTDOJO_ENGAGEMENT_NAME" envDefault:"build"`
    ENGAGEMENT_BUILD_ID  string `env:"TRIVY_DEFECTDOJO_ENGAGEMENT_BUILD_ID"`
    ENGAGEMENT_SROURCE_CODE_URI  string `env:"TRIVY_DEFECTDOJO_ENGAGEMENT_SROURCE_CODE_URI"`
    ENGAGEMENT_TAGS  string `env:"TRIVY_DEFECTDOJO_ENGAGEMENT_TAGS"`
    IMPORT_BRANCH_TAG  string `env:"TRIVY_DEFECTDOJO_IMPORT_BRANCH_TAG"`
    IMPORT_TAGS  string `env:"TRIVY_DEFECTDOJO_IMPORT_TAGS"`
    IMPORT_COMMIT_HASH  string `env:"TRIVY_DEFECTDOJO_IMPORT_COMMIT_HASH"`
    IMPORT_BUILD_ID  string `env:"TRIVY_DEFECTDOJO_IMPORT_BUILD_ID"`
	IMPORT_REPORT_JSON  string `env:"TRIVY_DEFECTDOJO_IMPORT_REPORT_JSON" envDefault:"trivy.report.json"`
	IMPORT_AUTO_CREATE bool `env:"TRIVY_DEFECTDOJO_IMPORT_AUTO_CREATE" envDefault:"false"`
	TEST_NAME int `env:"TRIVY_DEFECTDOJO_TEST_NAME" envDefault:"test"`
	TEST_ID int `env:"TRIVY_DEFECTDOJO_TEST_ID" envDefault:"0"`
	MODE_REIMPORT bool `env:"TRIVY_DEFECTDOJO_MODE_REIMPORT" envDefault:"false"`
}

var cfg = Config{};

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
    if err := env.Parse(&cfg); err != nil {
		return err
    }

	client := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	dj, err := defectdojo.NewDojoClient(cfg.URL, cfg.APIKEY, client)
	if err != nil {
		return err
	}

	ctx := context.Background()

	if(cfg.PRODUCT_ID == 0 && len(cfg.PRODUCT_NAME) == 0 || cfg.ENGAGEMENT_ID ==0 && len(cfg.ENGAGEMENT_NAME) == 0 ) { 
		fmt.Println("TRIVY_DEFECTDOJO_PRODUCT_ID or TRIVY_DEFECTDOJO_PRODUCT_NAME is set", cfg.PRODUCT_NAME)
		return err
	}

	manageProduct(ctx,dj)
	manageEngagement(ctx,dj)
	
	test := manageTests(ctx,dj)
	if  test == 0 {
		manageImportScan(ctx,dj)	
	} else {
		manageReImportScan(ctx,dj,test)	
	}

	return nil
}



func manageProduct(ctx context.Context, dj *defectdojo.Client) {
	
	if(cfg.PRODUCT_ID == 0) {
		opts := &defectdojo.ProductsOptions{
			Limit:    1,
			Name: url.QueryEscape(cfg.PRODUCT_NAME),
		}
	
		resp, err := dj.Products.List(ctx, opts)
		if err != nil {
			fmt.Println("product:list:", err)
			return
		}
	
		products := *resp.Results
		if( *resp.Count > 0) {
			cfg.PRODUCT_ID = *products[0].ID
		} 
	}

	if(cfg.PRODUCT_ID == 0) {
					
		if(cfg.PRODUCT_TYPE_ID == 0) {
				
			opts := &defectdojo.ProductTypesOptions{
				Name: url.QueryEscape(cfg.PRODUCT_TYPE_NAME),
			}

			resp, err := dj.ProductTypes.List(ctx, opts)
			if err != nil {
				fmt.Println("ProductType:", err)
				return
			}
		
			productTypes := *resp.Results
			if( *resp.Count > 0) {
				cfg.PRODUCT_TYPE_ID = *productTypes[0].Id
			}

		} else {
			_, err := dj.ProductTypes.Read(ctx, cfg.PRODUCT_TYPE_ID)
			if err != nil {
				fmt.Println("ProductType:", err)
				return
			}
		}
		
		
		if(cfg.PRODUCT_TYPE_ID == 0) {
				
			productType := &defectdojo.ProductType{
				Name: &cfg.PRODUCT_TYPE_NAME,
			}

			resp, err := dj.ProductTypes.Create(ctx, productType)
			if err != nil {
				fmt.Println("ProductType:", err)
				return
			}
			fmt.Println("ProductType created !")			
			cfg.PRODUCT_TYPE_ID = *resp.Id
		}


		product := &defectdojo.Product{
			Name: &cfg.PRODUCT_NAME,
			ProdType: &cfg.PRODUCT_TYPE_ID,
			Description: defectdojo.Str("Change Me !"),
		}

		resp, err := dj.Products.Create(ctx, product)
		if err != nil {
			fmt.Println("Product:", err)
			return
		}
		fmt.Println("Product created !")			
		cfg.PRODUCT_ID = *resp.ID
	}


	product, err := dj.Products.Read(ctx, cfg.PRODUCT_ID)
	if err != nil {
		fmt.Println("product:read:", err)
		return
	}

	fmt.Println("Product:", string(*product.Name))
}

func manageEngagement(ctx context.Context, dj *defectdojo.Client) {

	if(cfg.ENGAGEMENT_ID > 0) {
		_, err := dj.Engagements.Read(ctx, cfg.ENGAGEMENT_ID)
		if err != nil {
			fmt.Println("Engagement:", err)
			cfg.ENGAGEMENT_ID = 0
		}
	}

	if(cfg.ENGAGEMENT_ID == 0) {
		opts2 := &defectdojo.EngagementsOptions{
			Limit:    1,
			Name: url.QueryEscape(cfg.ENGAGEMENT_NAME),
			Product: cfg.PRODUCT_ID,
		}

		resp, err := dj.Engagements.List(ctx, opts2)
		if err != nil {
			fmt.Println("Engagement:", err)
			return
		}
	
		engagements := *resp.Results
		if( *resp.Count > 0) {
			cfg.ENGAGEMENT_ID = *engagements[0].Id
		}
	} 

	if(cfg.ENGAGEMENT_ID == 0) {
		targetStart := time.Now()
		targetEnd := targetStart.AddDate(1, 0, 0)
		
		targetStartFormatted := fmt.Sprintf("%d-%02d-%02d", targetStart.Year(), targetStart.Month(), targetStart.Day())
		targetEndFormatted := fmt.Sprintf("%d-%02d-%02d", targetEnd.Year(), targetEnd.Month(), targetEnd.Day())

		arr := strings.FieldsFunc(cfg.ENGAGEMENT_TAGS, func(r rune) bool {
		   return r == ','
		})

		engagement := &defectdojo.Engagement{
			Name: &cfg.ENGAGEMENT_NAME,
			Product: &cfg.PRODUCT_ID,
			Tags: defectdojo.Slice(arr),
			TargetStart: defectdojo.Str(targetStartFormatted),
			TargetEnd: defectdojo.Str(targetEndFormatted),
			SourceCodeManagementUri: defectdojo.Str(cfg.ENGAGEMENT_SROURCE_CODE_URI),
			EngagementType: defectdojo.Str("CI/CD"),
		}

		resp, err := dj.Engagements.Create(ctx, engagement)
		if err != nil {
			fmt.Println("Engagement:", err)
			return
		}
		fmt.Println("Engagement created !")			
		cfg.ENGAGEMENT_ID = *resp.Id
	} 

	engagement, err := dj.Engagements.Read(ctx, cfg.ENGAGEMENT_ID)
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

func manageTests(ctx context.Context, dj *defectdojo.Client) int {

	if(cfg.ENGAGEMENT_ID > 0) {
		_, err := dj.TestTypes.Read(ctx, cfg.TEST_ID)
		if err != nil {
			fmt.Println("Engagement:", err)
			cfg.ENGAGEMENT_ID = 0
		}
	}



	return 0;
}

func manageImportScan(ctx context.Context, dj *defectdojo.Client) {

	arr := strings.FieldsFunc(cfg.IMPORT_TAGS, func(r rune) bool {
		return r == ' '
	 })

	scan := &defectdojo.ImportScan{
		ProductId:         defectdojo.Int(cfg.PRODUCT_ID),
		Engagement:        defectdojo.Int(cfg.ENGAGEMENT_ID),
		ScanType:          defectdojo.Str("Trivy Scan"),
		BranchTag:         defectdojo.Str(cfg.IMPORT_BRANCH_TAG),
		CommitHash:        defectdojo.Str(cfg.IMPORT_COMMIT_HASH),
		BuildId:           defectdojo.Str(cfg.IMPORT_BUILD_ID),
		Tags:              defectdojo.Slice(arr),
		File:              defectdojo.Str(cfg.IMPORT_REPORT_JSON),
		AutoCreateContext: defectdojo.Bool(cfg.IMPORT_AUTO_CREATE),
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

	fmt.Println("ImportScan:",string(cfg.IMPORT_REPORT_JSON))
	fmt.Println(string(b))
}

func manageReImportScan(ctx context.Context, dj *defectdojo.Client, testId int) {

	arr := strings.FieldsFunc(cfg.IMPORT_TAGS, func(r rune) bool {
		return r == ' '
	 })

	scan := &defectdojo.ReImportScan{
		ProductId:         defectdojo.Int(cfg.PRODUCT_ID),
		EngagementId:      defectdojo.Int(cfg.ENGAGEMENT_ID),
		ScanType:          defectdojo.Str("Trivy Scan"),
		TestTitle:         defectdojo.Str("Trivy Scan"),
		BranchTag:         defectdojo.Str(cfg.IMPORT_BRANCH_TAG),
		CommitHash:        defectdojo.Str(cfg.IMPORT_COMMIT_HASH),
		BuildId:           defectdojo.Str(cfg.IMPORT_BUILD_ID),
		Tags:              defectdojo.Slice(arr),
		File:              defectdojo.Str(cfg.IMPORT_REPORT_JSON),
		AutoCreateContext: defectdojo.Bool(cfg.IMPORT_AUTO_CREATE),
		TestId: defectdojo.Int(testId),
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

	fmt.Println("ReImportScan:",string(cfg.IMPORT_REPORT_JSON))
	fmt.Println(string(b))
}
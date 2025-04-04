// importscan demonstrates the process of uploading a scan report into DefectDojo.
//
// Details of the import are defined by an ImportScan struct.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"log"
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
    BRANCH_TAG  string `env:"TRIVY_DEFECTDOJO_BRANCH_TAG"`
    COMMIT_HASH  string `env:"TRIVY_DEFECTDOJO_COMMIT_HASH"`
	REPORT_JSON  string `env:"TRIVY_DEFECTDOJO_REPORT_JSON" envDefault:"trivy.report.json"`
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
	manageImportScan(ctx,dj)	

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

		engagement := &defectdojo.Engagement{
			Name: &cfg.ENGAGEMENT_NAME,
			Product: &cfg.PRODUCT_ID,
			Tags: defectdojo.Slice([]string{"Trivy"}),
			TargetStart: defectdojo.Str(targetStartFormatted),
			TargetEnd: defectdojo.Str(targetEndFormatted),
			BranchTag: defectdojo.Str(cfg.BRANCH_TAG),
			CommitHash: defectdojo.Str(cfg.COMMIT_HASH),
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

func manageImportScan(ctx context.Context, dj *defectdojo.Client) {

	scan := &defectdojo.ImportScan{
		ProductId:         defectdojo.Int(cfg.PRODUCT_ID),
		Engagement:        defectdojo.Int(cfg.ENGAGEMENT_ID),
		AutoCreateContext: defectdojo.Bool(true),
		File:              defectdojo.Str(cfg.REPORT_JSON),
		ScanType:          defectdojo.Str("Trivy Scan"),
		BranchTag:         defectdojo.Str(cfg.BRANCH_TAG),
		CommitHash:         defectdojo.Str(cfg.COMMIT_HASH),
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

	fmt.Println("ImportScan:",string(cfg.REPORT_JSON))
	fmt.Println(string(b))
}
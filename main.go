package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"plugin"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/otyg/threagile/macros"
	add_build_pipeline "github.com/otyg/threagile/macros/built-in/add-build-pipeline"
	add_vault "github.com/otyg/threagile/macros/built-in/add-vault"
	pretty_print "github.com/otyg/threagile/macros/built-in/pretty-print"
	remove_unused_tags "github.com/otyg/threagile/macros/built-in/remove-unused-tags"
	seed_risk_tracking "github.com/otyg/threagile/macros/built-in/seed-risk-tracking"
	seed_tags "github.com/otyg/threagile/macros/built-in/seed-tags"
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/core"
	"github.com/otyg/threagile/model/criticality"
	"github.com/otyg/threagile/report"
	"github.com/otyg/threagile/support"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

const keepDiagramSourceFiles = false
const defaultGraphvizDPI, maxGraphvizDPI = 120, 240

const backupHistoryFilesToKeep = 50

const baseFolder, reportFilename, excelRisksFilename, excelTagsFilename, jsonRisksFilename, jsonTechnicalAssetsFilename, jsonStatsFilename, dataFlowDiagramFilenameDOT, dataFlowDiagramFilenamePNG, dataAssetDiagramFilenameDOT, dataAssetDiagramFilenamePNG, graphvizDataFlowDiagramConversionCall, graphvizDataAssetDiagramConversionCall = "/data", "report.pdf", "risks.xlsx", "tags.xlsx", "risks.json", "technical-assets.json", "stats.json", "data-flow-diagram.gv", "data-flow-diagram.png", "data-asset-diagram.gv", "data-asset-diagram.png", "render-data-flow-diagram.sh", "render-data-asset-diagram.sh"

var globalLock sync.Mutex
var successCount, errorCount = 0, 0

var modelInput model.ModelInput

var drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = true

var buildTimestamp = ""

var modelFilename, templateFilename /*, diagramFilename, reportFilename, graphvizConversion*/ *string
var createExampleModel, createStubModel, createEditingSupport, verbose, ignoreOrphanedRiskTracking, generateDataFlowDiagram, generateDataAssetDiagram, generateRisksJSON, generateTechnicalAssetsJSON, generateStatsJSON, generateRisksExcel, generateTagsExcel, generateReportPDF, generateDefectdojoGeneric *bool
var outputDir, raaPlugin, skipRiskRules, riskRulesPlugins, executeModelMacro *string
var builtinRiskRulesPlugins map[string]model.RiskRule
var diagramDPI, serverPort *int

var deferredRiskTrackingDueToWildcardMatching = make(map[string]model.RiskTracking)

func applyRiskGeneration() {
	if *verbose {
		fmt.Println("Applying risk generation")
	}
	skippedRules := make(map[string]interface{})
	if len(*skipRiskRules) > 0 {
		for _, id := range strings.Split(*skipRiskRules, ",") {
			skippedRules[id] = true
		}
	}

	for id, riskPlugin := range builtinRiskRulesPlugins {
		if _, ok := skippedRules[riskPlugin.Category().Id]; ok {
			fmt.Println("Skipping risk rule:", id)
			delete(skippedRules, id)
		} else {
			model.AddToListOfSupportedTags(riskPlugin.SupportedTags())
			risks := riskPlugin.GenerateRisks()
			if len(risks) > 0 {
				model.GeneratedRisksByCategory[riskPlugin.Category()] = risks
			}
		}
	}

	if len(skippedRules) > 0 {
		keys := make([]string, 0)
		for k := range skippedRules {
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			log.Println("Unknown risk rules to skip:", keys)
		}
	}

	// save also in map keyed by synthetic risk-id
	for _, category := range model.SortedRiskCategories() {
		risks := model.SortedRisksOfCategory(category)
		for _, risk := range risks {
			model.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

func checkRiskTracking() {
	if *verbose {
		fmt.Println("Checking risk tracking")
	}
	for _, tracking := range model.ParsedModelRoot.RiskTracking {
		if _, ok := model.GeneratedRisksBySyntheticId[tracking.SyntheticRiskId]; !ok {
			if *ignoreOrphanedRiskTracking {
				fmt.Println("Risk tracking references unknown risk (risk id not found): " + tracking.SyntheticRiskId)
			} else {
				panic(errors.New("Risk tracking references unknown risk (risk id not found) - you might want to use the option -ignore-orphaned-risk-tracking: " + tracking.SyntheticRiskId +
					"\n\nNOTE: For risk tracking each risk-id needs to be defined (the string with the @ sign in it). " +
					"These unique risk IDs are visible in the PDF report (the small grey string under each risk), " +
					"the Excel (column \"ID\"), as well as the JSON responses. Some risk IDs have only one @ sign in them, " +
					"while others multiple. The idea is to allow for unique but still speaking IDs. Therefore each risk instance " +
					"creates its individual ID by taking all affected elements causing the risk to be within an @-delimited part. " +
					"Using wildcards (the * sign) for parts delimited by @ signs allows to handle groups of certain risks at once. " +
					"Best is to lookup the IDs to use in the created Excel file. Alternatively a model macro \"seed-risk-tracking\" " +
					"is available that helps in initially seeding the risk tracking part here based on already identified and not yet handled risks."))
			}
		}
	}

	// save also the risk-category-id and risk-status directly in the risk for better JSON marshalling
	for category, _ := range model.GeneratedRisksByCategory {
		for i, _ := range model.GeneratedRisksByCategory[category] {
			model.GeneratedRisksByCategory[category][i].CategoryId = category.Id
			model.GeneratedRisksByCategory[category][i].RiskStatus = model.GeneratedRisksByCategory[category][i].GetRiskTrackingStatusDefaultingUnchecked()
		}
	}
}

// === Error handling stuff ========================================

func main() {
	parseCommandlineArgs()
	if *serverPort > 0 {
		startServer()
	} else {
		doIt(*modelFilename, *outputDir)
	}
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func unzip(src string, dest string) ([]string, error) {
	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {
		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)
		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}
		filenames = append(filenames, fpath)
		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		_, err = io.Copy(outFile, rc)
		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()
		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

// ZipFiles compresses one or many files into a single zip archive file.
// Param 1: filename is the output zip file's name.
// Param 2: files is a list of files to add to the zip.
func zipFiles(filename string, files []string) error {
	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	// Add files to zip
	for _, file := range files {
		if err = addFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	return nil
}

func addFileToZip(zipWriter *zip.Writer, filename string) error {
	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileToZip.Close()

	// Get the file information
	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	//header.Name = filename

	// Change to deflate to gain better compression
	// see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, fileToZip)
	return err
}

func doIt(inputFilename string, outputDirectory string) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *verbose {
				log.Println(err)
			}
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
	}()
	if len(*executeModelMacro) > 0 {
		printLogo()
	} else {
		if *verbose {
			fmt.Println("Writing into output directory:", outputDirectory)
		}
	}

	model.Init()
	parseModel(inputFilename)
	introTextRAA := applyRAA()
	loadRiskRulePlugins()
	applyRiskGeneration()
	applyWildcardRiskTrackingEvaluation()
	checkRiskTracking()

	if len(*executeModelMacro) > 0 {
		macros.ExecuteModelMacro(executeModelMacro, modelInput, inputFilename)
	}

	renderDataFlowDiagram, renderDataAssetDiagram, renderRisksJSON, renderTechnicalAssetsJSON, renderStatsJSON, renderRisksExcel, renderTagsExcel, renderPDF, renderDefectDojo := *generateDataFlowDiagram, *generateDataAssetDiagram, *generateRisksJSON, *generateTechnicalAssetsJSON, *generateStatsJSON, *generateRisksExcel, *generateTagsExcel, *generateReportPDF, *generateDefectdojoGeneric
	if renderPDF { // as the PDF report includes both diagrams
		renderDataFlowDiagram, renderDataAssetDiagram = true, true
	}

	// Data-flow Diagram rendering
	if renderDataFlowDiagram {
		report.RenderDataFlowDiagram(outputDirectory, keepDiagramSourceFiles, diagramDPI, verbose)
	}
	// Data Asset Diagram rendering
	if renderDataAssetDiagram {
		report.RenderDataAssetDiagram(outputDirectory, dataAssetDiagramFilenameDOT, keepDiagramSourceFiles, diagramDPI, verbose)
	}
	if renderDefectDojo {
		if *verbose {
			fmt.Println("Writing risks defectdojo generic json")
		}
		report.WriteDefectdojoGeneric(outputDirectory + "/defectdojo.json")
		report.WriteOpenSarif(outputDirectory + "/risks.sarif")
	}
	// risks as risks json
	if renderRisksJSON {
		if *verbose {
			fmt.Println("Writing risks json")
		}
		report.WriteRisksJSON(outputDirectory + "/" + jsonRisksFilename)
	}

	// technical assets json
	if renderTechnicalAssetsJSON {
		if *verbose {
			fmt.Println("Writing technical assets json")
		}
		report.WriteTechnicalAssetsJSON(outputDirectory + "/" + jsonTechnicalAssetsFilename)
	}

	// risks as risks json
	if renderStatsJSON {
		if *verbose {
			fmt.Println("Writing stats json")
		}
		report.WriteStatsJSON(outputDirectory + "/" + jsonStatsFilename)
	}

	// risks Excel
	if renderRisksExcel {
		if *verbose {
			fmt.Println("Writing risks excel")
		}
		report.WriteRisksExcelToFile(outputDirectory + "/" + excelRisksFilename)
	}

	// tags Excel
	if renderTagsExcel {
		if *verbose {
			fmt.Println("Writing tags excel")
		}
		report.WriteTagsExcelToFile(outputDirectory + "/" + excelTagsFilename)
	}

	if renderPDF {
		// hash the YAML input file
		f, err := os.Open(inputFilename)
		support.CheckErr(err)
		defer f.Close()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			panic(err)
		}
		modelHash := hex.EncodeToString(hasher.Sum(nil))
		// report PDF
		if *verbose {
			fmt.Println("Writing report pdf")
		}
		report.WriteReportPDF(outputDirectory+"/"+reportFilename,
			*templateFilename,
			outputDirectory+"/"+dataFlowDiagramFilenamePNG,
			outputDirectory+"/"+dataAssetDiagramFilenamePNG,
			inputFilename,
			*skipRiskRules,
			buildTimestamp,
			modelHash,
			introTextRAA,
			builtinRiskRulesPlugins)
	}
}

func applyRAA() string {
	if *verbose {
		fmt.Println("Applying RAA calculation:", *raaPlugin)
	}
	// determine plugin to load
	// load plugin: open the ".so" file to load the symbols
	plug, err := plugin.Open(*raaPlugin)
	support.CheckErr(err)
	// look up a symbol (an exported function or variable): in this case, function CalculateRAA
	symCalculateRAA, err := plug.Lookup("CalculateRAA")
	support.CheckErr(err)
	// use the plugin
	raaCalcFunc, ok := symCalculateRAA.(func() string) // symCalculateRAA.(func(model.ParsedModel) string)
	if !ok {
		panic(errors.New("RAA plugin has no 'CalculateRAA() string' function"))
	}
	// call it
	return raaCalcFunc()
}
func loadRiskRulePlugins() {
	builtinRiskRulesPlugins = make(map[string]model.RiskRule)
	pluginFiles, err := filepath.Glob("risk-plugins/*.so")
	if err != nil {
		panic(errors.New(err.Error()))
	}
	for _, pluginFile := range pluginFiles {
		_, err := os.Stat(pluginFile)
		if os.IsNotExist(err) {
			log.Fatal("Risk rule implementation file not found: ", pluginFile)
		}
		plug, err := plugin.Open(pluginFile)
		support.CheckErr(err)
		// look up a symbol (an exported function or variable): in this case variable CustomRiskRule
		symRiskRule, err := plug.Lookup("RiskRule")
		support.CheckErr(err)
		// register the risk rule plugin for later use: in this case interface type model.RiskRule (defined above)
		symRiskRuleVar, ok := symRiskRule.(model.RiskRule)
		if !ok {
			panic(errors.New("Risk rule plugin has no 'RiskRule' variable" + symRiskRuleVar.Category().Id))
		}
		// simply add to a map (just convenience) where key is the category id and value the rule's execution function
		ruleID := symRiskRuleVar.Category().Id
		builtinRiskRulesPlugins[ruleID] = symRiskRuleVar
		if *verbose {
			fmt.Println("Risk rule loaded:", ruleID)
		}
	}
}

func analyze(context *gin.Context) {
	execute(context, false)
}
func check(context *gin.Context) {
	_, ok := execute(context, true)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"message": "model is ok",
		})
	}
}

func execute(context *gin.Context, dryRun bool) (yamlContent []byte, ok bool) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			errorCount++
			err = r.(error)
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(context.DefaultQuery("dpi", strconv.Itoa(defaultGraphvizDPI)))
	support.CheckErr(err)

	fileUploaded, header, err := context.Request.FormFile("file")
	support.CheckErr(err)

	if header.Size > 50000000 {
		msg := "maximum model upload file size exceeded (denial-of-service protection)"
		log.Println(msg)
		context.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": msg,
		})
		return yamlContent, false
	}

	filenameUploaded := strings.TrimSpace(header.Filename)

	tmpInputDir, err := ioutil.TempDir(model.TempFolder, "threagile-input-")
	support.CheckErr(err)
	defer os.RemoveAll(tmpInputDir)

	tmpModelFile, err := ioutil.TempFile(tmpInputDir, "threagile-model-*")
	support.CheckErr(err)
	defer os.Remove(tmpModelFile.Name())
	_, err = io.Copy(tmpModelFile, fileUploaded)
	support.CheckErr(err)

	yamlFile := tmpModelFile.Name()

	if strings.ToLower(filepath.Ext(filenameUploaded)) == ".zip" {
		// unzip first (including the resources like images etc.)
		if *verbose {
			fmt.Println("Decompressing uploaded archive")
		}
		filenamesUnzipped, err := unzip(tmpModelFile.Name(), tmpInputDir)
		support.CheckErr(err)
		found := false
		for _, name := range filenamesUnzipped {
			if strings.ToLower(filepath.Ext(name)) == ".yaml" {
				yamlFile = name
				found = true
				break
			}
		}
		if !found {
			panic(errors.New("no yaml file found in uploaded archive"))
		}
	}

	tmpOutputDir, err := ioutil.TempDir(model.TempFolder, "threagile-output-")
	support.CheckErr(err)
	defer os.RemoveAll(tmpOutputDir)

	tmpResultFile, err := ioutil.TempFile(model.TempFolder, "threagile-result-*.zip")
	support.CheckErr(err)
	defer os.Remove(tmpResultFile.Name())

	if dryRun {
		doItViaRuntimeCall(yamlFile, tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, true, true, true, true, 40)
	} else {
		doItViaRuntimeCall(yamlFile, tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, true, true, true, true, true, true, true, true, true, dpi)
	}
	support.CheckErr(err)

	yamlContent, err = ioutil.ReadFile(yamlFile)
	support.CheckErr(err)
	err = ioutil.WriteFile(tmpOutputDir+"/threagile.yaml", yamlContent, 0400)
	support.CheckErr(err)

	if !dryRun {
		files := []string{
			tmpOutputDir + "/threagile.yaml",
			tmpOutputDir + "/" + dataFlowDiagramFilenamePNG,
			tmpOutputDir + "/" + dataAssetDiagramFilenamePNG,
			tmpOutputDir + "/" + reportFilename,
			tmpOutputDir + "/" + excelRisksFilename,
			tmpOutputDir + "/" + excelTagsFilename,
			tmpOutputDir + "/" + jsonRisksFilename,
			tmpOutputDir + "/" + jsonTechnicalAssetsFilename,
			tmpOutputDir + "/" + jsonStatsFilename,
		}
		if keepDiagramSourceFiles {
			files = append(files, tmpOutputDir+"/"+dataFlowDiagramFilenameDOT)
			files = append(files, tmpOutputDir+"/"+dataAssetDiagramFilenameDOT)
		}
		err = zipFiles(tmpResultFile.Name(), files)
		support.CheckErr(err)
		if *verbose {
			log.Println("Streaming back result file: " + tmpResultFile.Name())
		}
		context.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
	}
	successCount++
	return yamlContent, true
}

// ultimately to avoid any in-process memory and/or data leaks by the used third party libs like PDF generation: exec and quit
func doItViaRuntimeCall(modelFile string, outputDir string, executeModelMacro string, raaPlugin string, skipRiskRules string, ignoreOrphanedRiskTracking bool,
	generateDataFlowDiagram, generateDataAssetDiagram, generateReportPdf, generateRisksExcel, generateTagsExcel, generateRisksJSON, generateTechnicalAssetsJSON, generateDefectdojo, generateStatsJSON bool,
	dpi int) {
	// Remember to also add the same args to the exec based sub-process calls!
	var cmd *exec.Cmd
	args := []string{"-model", modelFile, "-output", outputDir, "-execute-model-macro", executeModelMacro, "-raa-plugin", raaPlugin, "-skip-risk-rules", skipRiskRules, "-diagram-dpi", strconv.Itoa(dpi)}
	if *verbose {
		args = append(args, "-verbose")
	}
	if ignoreOrphanedRiskTracking { // TODO why add all them as arguments, when they are also variables on outer level?
		args = append(args, "-ignore-orphaned-risk-tracking")
	}
	if generateDataFlowDiagram {
		args = append(args, "-generate-data-flow-diagram")
	}
	if generateDataAssetDiagram {
		args = append(args, "-generate-data-asset-diagram")
	}
	if generateReportPdf {
		args = append(args, "-generate-report-pdf")
	}
	if generateDefectdojo {
		args = append(args, "-generate-defectdojo-json")
	}
	if generateRisksExcel {
		args = append(args, "-generate-risks-excel")
	}
	if generateTagsExcel {
		args = append(args, "-generate-tags-excel")
	}
	if generateRisksJSON {
		args = append(args, "-generate-risks-json")
	}
	if generateTechnicalAssetsJSON {
		args = append(args, "-generate-technical-assets-json")
	}
	if generateStatsJSON {
		args = append(args, "-generate-stats-json")
	}
	self := os.Args[0]
	cmd = exec.Command(self, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(errors.New(string(out)))
	} else {
		if *verbose && len(out) > 0 {
			fmt.Println("---")
			fmt.Print(string(out))
			fmt.Println("---")
		}
	}
}

func startServer() {
	router := gin.Default()
	router.LoadHTMLGlob("server/static/*.html")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.HEAD("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.StaticFile("/threagile.png", "server/static/threagile.png")
	router.StaticFile("/site.webmanifest", "server/static/site.webmanifest")
	router.StaticFile("/favicon.ico", "server/static/favicon.ico")
	router.StaticFile("/favicon-32x32.png", "server/static/favicon-32x32.png")
	router.StaticFile("/favicon-16x16.png", "server/static/favicon-16x16.png")
	router.StaticFile("/apple-touch-icon.png", "server/static/apple-touch-icon.png")
	router.StaticFile("/android-chrome-512x512.png", "server/static/android-chrome-512x512.png")
	router.StaticFile("/android-chrome-192x192.png", "server/static/android-chrome-192x192.png")

	router.StaticFile("/schema.json", "schema.json")
	router.StaticFile("/live-templates.txt", "live-templates.txt")
	router.StaticFile("/openapi.yaml", "openapi.yaml")
	router.StaticFile("/swagger-ui/", "server/static/swagger-ui/index.html")
	router.StaticFile("/swagger-ui/index.html", "server/static/swagger-ui/index.html")
	router.StaticFile("/swagger-ui/oauth2-redirect.html", "server/static/swagger-ui/oauth2-redirect.html")
	router.StaticFile("/swagger-ui/swagger-ui.css", "server/static/swagger-ui/swagger-ui.css")
	router.StaticFile("/swagger-ui/swagger-ui.js", "server/static/swagger-ui/swagger-ui.js")
	router.StaticFile("/swagger-ui/swagger-ui-bundle.js", "server/static/swagger-ui/swagger-ui-bundle.js")
	router.StaticFile("/swagger-ui/swagger-ui-standalone-preset.js", "server/static/swagger-ui/swagger-ui-standalone-preset.js")

	router.GET("/threagile-example-model.yaml", exampleFile)
	router.GET("/threagile-stub-model.yaml", stubFile)

	router.GET("/meta/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	router.GET("/meta/version", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"version":         model.ThreagileVersion,
			"build_timestamp": buildTimestamp,
		})
	})
	router.GET("/meta/types", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"quantity":                     arrayOfStringValues(model.QuantityValues()),
			"confidentiality":              arrayOfStringValues(confidentiality.ConfidentialityValues()),
			"criticality":                  arrayOfStringValues(criticality.CriticalityValues()),
			"technical_asset_type":         arrayOfStringValues(model.TechnicalAssetTypeValues()),
			"technical_asset_size":         arrayOfStringValues(model.TechnicalAssetSizeValues()),
			"authorization":                arrayOfStringValues(model.AuthorizationValues()),
			"authentication":               arrayOfStringValues(model.AuthenticationValues()),
			"usage":                        arrayOfStringValues(model.UsageValues()),
			"encryption":                   arrayOfStringValues(model.EncryptionStyleValues()),
			"data_format":                  arrayOfStringValues(model.DataFormatValues()),
			"protocol":                     arrayOfStringValues(model.ProtocolValues()),
			"technical_asset_technology":   arrayOfStringValues(model.TechnicalAssetTechnologyValues()),
			"technical_asset_machine":      arrayOfStringValues(model.TechnicalAssetMachineValues()),
			"trust_boundary_type":          arrayOfStringValues(model.TrustBoundaryTypeValues()),
			"data_breach_probability":      arrayOfStringValues(model.DataBreachProbabilityValues()),
			"risk_severity":                arrayOfStringValues(model.RiskSeverityValues()),
			"risk_exploitation_likelihood": arrayOfStringValues(model.RiskExploitationLikelihoodValues()),
			"risk_exploitation_impact":     arrayOfStringValues(model.RiskExploitationImpactValues()),
			"risk_function":                arrayOfStringValues(model.RiskFunctionValues()),
			"risk_status":                  arrayOfStringValues(model.RiskStatusValues()),
			"stride":                       arrayOfStringValues(model.STRIDEValues()),
		})
	})

	// TODO router.GET("/meta/risk-rules", listRiskRules)
	// TODO router.GET("/meta/model-macros", listModelMacros)

	router.GET("/meta/stats", stats)

	router.POST("/direct/analyze", analyze)
	router.POST("/direct/check", check)
	router.GET("/direct/stub", stubFile)

	router.POST("/auth/keys", createKey)
	router.DELETE("/auth/keys", deleteKey)
	router.POST("/auth/tokens", createToken)
	router.DELETE("/auth/tokens", deleteToken)

	router.POST("/models", createNewModel)
	router.GET("/models", listModels)
	router.DELETE("/models/:model-id", deleteModel)
	router.GET("/models/:model-id", getModel)
	router.PUT("/models/:model-id", importModel)
	router.GET("/models/:model-id/data-flow-diagram", streamDataFlowDiagram)
	router.GET("/models/:model-id/data-asset-diagram", streamDataAssetDiagram)
	router.GET("/models/:model-id/report-pdf", streamReportPDF)
	router.GET("/models/:model-id/risks-excel", streamRisksExcel)
	router.GET("/models/:model-id/tags-excel", streamTagsExcel)
	router.GET("/models/:model-id/risks", streamRisksJSON)
	router.GET("/models/:model-id/technical-assets", streamTechnicalAssetsJSON)
	router.GET("/models/:model-id/stats", streamStatsJSON)
	router.GET("/models/:model-id/analysis", analyzeModelOnServerDirectly)

	router.GET("/models/:model-id/cover", getCover)
	router.PUT("/models/:model-id/cover", setCover)
	router.GET("/models/:model-id/overview", getOverview)
	router.PUT("/models/:model-id/overview", setOverview)
	//router.GET("/models/:model-id/questions", getQuestions)
	//router.PUT("/models/:model-id/questions", setQuestions)
	router.GET("/models/:model-id/abuse-cases", getAbuseCases)
	router.PUT("/models/:model-id/abuse-cases", setAbuseCases)
	router.GET("/models/:model-id/security-requirements", getSecurityRequirements)
	router.PUT("/models/:model-id/security-requirements", setSecurityRequirements)
	//router.GET("/models/:model-id/tags", getTags)
	//router.PUT("/models/:model-id/tags", setTags)

	router.GET("/models/:model-id/data-assets", getDataAssets)
	router.POST("/models/:model-id/data-assets", createNewDataAsset)
	router.GET("/models/:model-id/data-assets/:data-asset-id", getDataAsset)
	router.PUT("/models/:model-id/data-assets/:data-asset-id", setDataAsset)
	router.DELETE("/models/:model-id/data-assets/:data-asset-id", deleteDataAsset)

	router.GET("/models/:model-id/trust-boundaries", getTrustBoundaries)
	//	router.POST("/models/:model-id/trust-boundaries", createNewTrustBoundary)
	//	router.GET("/models/:model-id/trust-boundaries/:trust-boundary-id", getTrustBoundary)
	//	router.PUT("/models/:model-id/trust-boundaries/:trust-boundary-id", setTrustBoundary)
	//	router.DELETE("/models/:model-id/trust-boundaries/:trust-boundary-id", deleteTrustBoundary)

	router.GET("/models/:model-id/shared-runtimes", getSharedRuntimes)
	router.POST("/models/:model-id/shared-runtimes", createNewSharedRuntime)
	router.GET("/models/:model-id/shared-runtimes/:shared-runtime-id", getSharedRuntime)
	router.PUT("/models/:model-id/shared-runtimes/:shared-runtime-id", setSharedRuntime)
	router.DELETE("/models/:model-id/shared-runtimes/:shared-runtime-id", deleteSharedRuntime)

	fmt.Println("Threagile server running...")
	router.Run(":" + strconv.Itoa(*serverPort)) // listen and serve on 0.0.0.0:8080 or whatever port was specified
}

func exampleFile(context *gin.Context) {
	example, err := ioutil.ReadFile("/app/threagile-example-model.yaml")
	support.CheckErr(err)
	context.Data(http.StatusOK, gin.MIMEYAML, example)
}

func stubFile(context *gin.Context) {
	stub, err := ioutil.ReadFile("/app/threagile-stub-model.yaml")
	support.CheckErr(err)
	context.Data(http.StatusOK, gin.MIMEYAML, addSupportedTags(stub)) // TODO use also the MIMEYAML way of serving YAML in model export?
}

func addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool, 0)
	for _, riskRule := range builtinRiskRulesPlugins {
		for _, tag := range riskRule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}
	tags := make([]string, 0, len(supportedTags))
	for t := range supportedTags {
		tags = append(tags, t)
	}
	if len(tags) == 0 {
		return input
	}
	sort.Strings(tags)
	if *verbose {
		fmt.Print("Supported tags of all risk rules: ")
		for i, tag := range tags {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(tag)
		}
		fmt.Println()
	}
	replacement := "tags_available:"
	for _, tag := range tags {
		replacement += "\n  - " + tag
	}
	return []byte(strings.Replace(string(input), "tags_available:", replacement, 1))
}

const keySize = 32

type timeoutStruct struct {
	xorRand                              []byte
	createdNanotime, lastAcessedNanotime int64
}

var mapTokenHashToTimeoutStruct = make(map[string]timeoutStruct)
var mapFolderNameToTokenHash = make(map[string]string)

func createToken(context *gin.Context) {
	folderName, key, ok := checkKeyToFolderName(context)
	if !ok {
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	if tokenHash, exists := mapFolderNameToTokenHash[folderName]; exists {
		// invalidate previous token
		delete(mapTokenHashToTimeoutStruct, tokenHash)
	}
	// create a strong random 256 bit value (used to xor)
	xorBytesArr := make([]byte, keySize)
	n, err := rand.Read(xorBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create token",
		})
		return
	}
	now := time.Now().UnixNano()
	token := xor(key, xorBytesArr)
	tokenHash := hashSHA256(token)
	housekeepingTokenMaps()
	mapTokenHashToTimeoutStruct[tokenHash] = timeoutStruct{
		xorRand:             xorBytesArr,
		createdNanotime:     now,
		lastAcessedNanotime: now,
	}
	mapFolderNameToTokenHash[folderName] = tokenHash
	context.JSON(http.StatusCreated, gin.H{
		"token": base64.RawURLEncoding.EncodeToString(token[:]),
	})
}

func deleteToken(context *gin.Context) {
	header := tokenHeader{}
	if err := context.ShouldBindHeader(&header); err != nil {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	deleteTokenHashFromMaps(hashSHA256(token))
	context.JSON(http.StatusOK, gin.H{
		"message": "token deleted",
	})
}

const extremeShortTimeoutsForTesting = false

func housekeepingTokenMaps() {
	now := time.Now().UnixNano()
	for tokenHash, val := range mapTokenHashToTimeoutStruct {
		if extremeShortTimeoutsForTesting {
			// remove all elements older than 1 minute (= 60000000000 ns) soft
			// and all elements older than 3 minutes (= 180000000000 ns) hard
			if now-val.lastAcessedNanotime > 60000000000 || now-val.createdNanotime > 180000000000 {
				fmt.Println("About to remove a token hash from maps")
				deleteTokenHashFromMaps(tokenHash)
			}
		} else {
			// remove all elements older than 30 minutes (= 1800000000000 ns) soft
			// and all elements older than 10 hours (= 36000000000000 ns) hard
			if now-val.lastAcessedNanotime > 1800000000000 || now-val.createdNanotime > 36000000000000 {
				deleteTokenHashFromMaps(tokenHash)
			}
		}
	}
}

func deleteTokenHashFromMaps(tokenHash string) {
	delete(mapTokenHashToTimeoutStruct, tokenHash)
	for folderName, check := range mapFolderNameToTokenHash {
		if check == tokenHash {
			delete(mapFolderNameToTokenHash, folderName)
			break
		}
	}
}

func xor(key []byte, xor []byte) []byte {
	if len(key) != len(xor) {
		panic(errors.New("key length not matching XOR length"))
	}
	result := make([]byte, len(xor))
	for i, b := range key {
		result[i] = b ^ xor[i]
	}
	return result
}

func analyzeModelOnServerDirectly(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer func() {
		unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *verbose {
				log.Println(err)
			}
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(context.DefaultQuery("dpi", strconv.Itoa(defaultGraphvizDPI)))
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}

	_, yamlText, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := ioutil.TempFile(model.TempFolder, "threagile-direct-analyze-*")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.Remove(tmpModelFile.Name())
	tmpOutputDir, err := ioutil.TempDir(model.TempFolder, "threagile-direct-analyze-")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.RemoveAll(tmpOutputDir)
	tmpResultFile, err := ioutil.TempFile(model.TempFolder, "threagile-result-*.zip")
	support.CheckErr(err)
	defer os.Remove(tmpResultFile.Name())

	err = ioutil.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)

	doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, true, true, true, true, true, true, true, true, true, dpi)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	err = ioutil.WriteFile(tmpOutputDir+"/threagile.yaml", []byte(yamlText), 0400)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}

	files := []string{
		tmpOutputDir + "/threagile.yaml",
		tmpOutputDir + "/" + dataFlowDiagramFilenamePNG,
		tmpOutputDir + "/" + dataAssetDiagramFilenamePNG,
		tmpOutputDir + "/" + reportFilename,
		tmpOutputDir + "/" + excelRisksFilename,
		tmpOutputDir + "/" + excelTagsFilename,
		tmpOutputDir + "/" + jsonRisksFilename,
		tmpOutputDir + "/" + jsonTechnicalAssetsFilename,
		tmpOutputDir + "/" + jsonStatsFilename,
	}
	if keepDiagramSourceFiles {
		files = append(files, tmpOutputDir+"/"+dataFlowDiagramFilenameDOT)
		files = append(files, tmpOutputDir+"/"+dataAssetDiagramFilenameDOT)
	}
	err = zipFiles(tmpResultFile.Name(), files)
	support.CheckErr(err)
	if *verbose {
		fmt.Println("Streaming back result file: " + tmpResultFile.Name())
	}
	context.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
}

type responseType int

const (
	dataFlowDiagram responseType = iota
	dataAssetDiagram
	reportPDF
	risksExcel
	tagsExcel
	risksJSON
	technicalAssetsJSON
	statsJSON
)

func streamDataFlowDiagram(context *gin.Context) {
	streamResponse(context, dataFlowDiagram)
}
func streamDataAssetDiagram(context *gin.Context) {
	streamResponse(context, dataAssetDiagram)
}
func streamReportPDF(context *gin.Context) {
	streamResponse(context, reportPDF)
}
func streamRisksExcel(context *gin.Context) {
	streamResponse(context, risksExcel)
}
func streamTagsExcel(context *gin.Context) {
	streamResponse(context, tagsExcel)
}
func streamRisksJSON(context *gin.Context) {
	streamResponse(context, risksJSON)
}
func streamTechnicalAssetsJSON(context *gin.Context) {
	streamResponse(context, technicalAssetsJSON)
}
func streamStatsJSON(context *gin.Context) {
	streamResponse(context, statsJSON)
}
func streamResponse(context *gin.Context, responseType responseType) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer func() {
		unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if *verbose {
				log.Println(err)
			}
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()
	dpi, err := strconv.Atoi(context.DefaultQuery("dpi", strconv.Itoa(defaultGraphvizDPI)))
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	_, yamlText, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := ioutil.TempFile(model.TempFolder, "threagile-render-*")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.Remove(tmpModelFile.Name())
	tmpOutputDir, err := ioutil.TempDir(model.TempFolder, "threagile-render-")
	if err != nil {
		handleErrorInServiceCall(err, context)
		return
	}
	defer os.RemoveAll(tmpOutputDir)
	err = ioutil.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)
	if responseType == dataFlowDiagram {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, true, false, false, false, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.File(tmpOutputDir + "/" + dataFlowDiagramFilenamePNG)
	} else if responseType == dataAssetDiagram {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, true, false, false, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.File(tmpOutputDir + "/" + dataAssetDiagramFilenamePNG)
	} else if responseType == reportPDF {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, true, false, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.FileAttachment(tmpOutputDir+"/"+reportFilename, reportFilename)
	} else if responseType == risksExcel {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, true, false, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.FileAttachment(tmpOutputDir+"/"+excelRisksFilename, excelRisksFilename)
	} else if responseType == tagsExcel {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, true, false, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.FileAttachment(tmpOutputDir+"/"+excelTagsFilename, excelTagsFilename)
	} else if responseType == risksJSON {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, true, false, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		json, err := ioutil.ReadFile(tmpOutputDir + "/" + jsonRisksFilename)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.Data(http.StatusOK, "application/json", json) // stream directly with JSON content-type in response instead of file download
	} else if responseType == technicalAssetsJSON {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, true, true, false, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		json, err := ioutil.ReadFile(tmpOutputDir + "/" + jsonTechnicalAssetsFilename)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.Data(http.StatusOK, "application/json", json) // stream directly with JSON content-type in response instead of file download
	} else if responseType == statsJSON {
		doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, *executeModelMacro, *raaPlugin, *skipRiskRules, *ignoreOrphanedRiskTracking, false, false, false, false, false, false, false, true, false, dpi)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		json, err := ioutil.ReadFile(tmpOutputDir + "/" + jsonStatsFilename)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		context.Data(http.StatusOK, "application/json", json) // stream directly with JSON content-type in response instead of file download
	}
}

// fully replaces threagile.yaml in sub-folder given by UUID
func importModel(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)

	uuid := context.Param("model-id") // UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	_, _, ok = readModel(context, uuid, key, folderNameOfKey)
	if ok {
		// first analyze it simply by executing the full risk process (just discard the result) to ensure that everything would work
		yamlContent, ok := execute(context, true)
		if ok {
			// if we're here, then no problem was raised, so ok to proceed
			ok = writeModelYAML(context, string(yamlContent), key, folderNameForModel(folderNameOfKey, uuid), "Model Import", false)
			if ok {
				context.JSON(http.StatusCreated, gin.H{
					"message": "model imported",
				})
			}
		}
	}
}

func stats(context *gin.Context) {
	keyCount, modelCount := 0, 0
	keyFolders, err := ioutil.ReadDir(baseFolder)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to collect stats",
		})
		return
	}
	for _, keyFolder := range keyFolders {
		if len(keyFolder.Name()) == 128 { // it's a sha512 token hash probably, so count it as token folder for the stats
			keyCount++
			modelFolders, err := ioutil.ReadDir(baseFolder + "/" + keyFolder.Name())
			if err != nil {
				log.Println(err)
				context.JSON(http.StatusInternalServerError, gin.H{
					"error": "unable to collect stats",
				})
				return
			}
			for _, modelFolder := range modelFolders {
				if len(modelFolder.Name()) == 36 { // it's a uuid model folder probably, so count it as model folder for the stats
					modelCount++
				}
			}
		}
	}
	// TODO collect and deliver more stats (old model count?) and health info
	context.JSON(http.StatusOK, gin.H{
		"key_count":     keyCount,
		"model_count":   modelCount,
		"success_count": successCount,
		"error_count":   errorCount,
	})
}

func getDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.Data_assets {
			if dataAsset.ID == context.Param("data-asset-id") {
				context.JSON(http.StatusOK, gin.H{
					title: dataAsset,
				})
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func deleteDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.Data_assets {
			if dataAsset.ID == context.Param("data-asset-id") {
				// also remove all usages of this data asset !!
				for _, techAsset := range modelInput.Technical_assets {
					if techAsset.Data_assets_processed != nil {
						for i, parsedChangeCandidateAsset := range techAsset.Data_assets_processed {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.Data_assets_processed[i:], techAsset.Data_assets_processed[i+1:])                           // Shift a[i+1:] left one index.
								techAsset.Data_assets_processed[len(techAsset.Data_assets_processed)-1] = ""                               // Erase last element (write zero value).
								techAsset.Data_assets_processed = techAsset.Data_assets_processed[:len(techAsset.Data_assets_processed)-1] // Truncate slice.
							}
						}
					}
					if techAsset.Data_assets_stored != nil {
						for i, parsedChangeCandidateAsset := range techAsset.Data_assets_stored {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.Data_assets_stored[i:], techAsset.Data_assets_stored[i+1:])                        // Shift a[i+1:] left one index.
								techAsset.Data_assets_stored[len(techAsset.Data_assets_stored)-1] = ""                            // Erase last element (write zero value).
								techAsset.Data_assets_stored = techAsset.Data_assets_stored[:len(techAsset.Data_assets_stored)-1] // Truncate slice.
							}
						}
					}
					if techAsset.Communication_links != nil {
						for title, commLink := range techAsset.Communication_links {
							for i, dataAssetSent := range commLink.Data_assets_sent {
								referencedAsset := fmt.Sprintf("%v", dataAssetSent)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.Communication_links[title].Data_assets_sent[i:], techAsset.Communication_links[title].Data_assets_sent[i+1:]) // Shift a[i+1:] left one index.
									techAsset.Communication_links[title].Data_assets_sent[len(techAsset.Communication_links[title].Data_assets_sent)-1] = ""     // Erase last element (write zero value).
									x := techAsset.Communication_links[title]
									x.Data_assets_sent = techAsset.Communication_links[title].Data_assets_sent[:len(techAsset.Communication_links[title].Data_assets_sent)-1] // Truncate slice.
									techAsset.Communication_links[title] = x
								}
							}
							for i, dataAssetReceived := range commLink.Data_assets_received {
								referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.Communication_links[title].Data_assets_received[i:], techAsset.Communication_links[title].Data_assets_received[i+1:]) // Shift a[i+1:] left one index.
									techAsset.Communication_links[title].Data_assets_received[len(techAsset.Communication_links[title].Data_assets_received)-1] = ""     // Erase last element (write zero value).
									x := techAsset.Communication_links[title]
									x.Data_assets_received = techAsset.Communication_links[title].Data_assets_received[:len(techAsset.Communication_links[title].Data_assets_received)-1] // Truncate slice.
									techAsset.Communication_links[title] = x
								}
							}
						}
					}
				}
				for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
					if indivRiskCat.Risks_identified != nil {
						for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
							if indivRiskInstance.Most_relevant_data_asset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
								x.Most_relevant_data_asset = "" // TODO needs more testing
								modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.Data_assets, title)
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Data Asset Deletion")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":            "data asset deleted",
						"id":                 dataAsset.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func setSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.Shared_runtimes {
			if sharedRuntime.ID == context.Param("shared-runtime-id") {
				payload := payloadSharedRuntime{}
				err := context.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					context.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				sharedRuntimeInput, ok := populateSharedRuntime(context, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the shared runtime from the map and re-insert it (with new key)
				delete(modelInput.Shared_runtimes, title)
				modelInput.Shared_runtimes[payload.Title] = sharedRuntimeInput
				idChanged := sharedRuntimeInput.ID != sharedRuntime.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
						if indivRiskCat.Risks_identified != nil {
							for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
								if indivRiskInstance.Most_relevant_shared_runtime == sharedRuntime.ID { // apply the ID change
									x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
									x.Most_relevant_shared_runtime = sharedRuntimeInput.ID // TODO needs more testing
									modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Shared Runtime Update")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":    "shared runtime updated",
						"id":         sharedRuntimeInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func setDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.Data_assets {
			if dataAsset.ID == context.Param("data-asset-id") {
				payload := payloadDataAsset{}
				err := context.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					context.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				dataAssetInput, ok := populateDataAsset(context, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the asset from the map and re-insert it (with new key)
				delete(modelInput.Data_assets, title)
				modelInput.Data_assets[payload.Title] = dataAssetInput
				idChanged := dataAssetInput.ID != dataAsset.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					// also update all usages to point to the new (changed) ID !!
					for techAssetTitle, techAsset := range modelInput.Technical_assets {
						if techAsset.Data_assets_processed != nil {
							for i, parsedChangeCandidateAsset := range techAsset.Data_assets_processed {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.Technical_assets[techAssetTitle].Data_assets_processed[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.Data_assets_stored != nil {
							for i, parsedChangeCandidateAsset := range techAsset.Data_assets_stored {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.Technical_assets[techAssetTitle].Data_assets_stored[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.Communication_links != nil {
							for title, commLink := range techAsset.Communication_links {
								for i, dataAssetSent := range commLink.Data_assets_sent {
									referencedAsset := fmt.Sprintf("%v", dataAssetSent)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.Technical_assets[techAssetTitle].Communication_links[title].Data_assets_sent[i] = dataAssetInput.ID
									}
								}
								for i, dataAssetReceived := range commLink.Data_assets_received {
									referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.Technical_assets[techAssetTitle].Communication_links[title].Data_assets_received[i] = dataAssetInput.ID
									}
								}
							}
						}
					}
					for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
						if indivRiskCat.Risks_identified != nil {
							for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
								if indivRiskInstance.Most_relevant_data_asset == dataAsset.ID { // apply the ID change
									x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
									x.Most_relevant_data_asset = dataAssetInput.ID // TODO needs more testing
									modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Data Asset Update")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":    "data asset updated",
						"id":         dataAssetInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func getSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.Shared_runtimes {
			if sharedRuntime.ID == context.Param("shared-runtime-id") {
				context.JSON(http.StatusOK, gin.H{
					title: sharedRuntime,
				})
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func createNewSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSharedRuntime{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.Shared_runtimes[payload.Title]; exists {
			context.JSON(http.StatusConflict, gin.H{
				"error": "shared runtime with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by it's "id", so do this uniqueness check also
		for _, runtime := range modelInput.Shared_runtimes {
			if runtime.ID == payload.Id {
				context.JSON(http.StatusConflict, gin.H{
					"error": "shared runtime with this id already exists",
				})
				return
			}
		}
		if !checkTechnicalAssetsExisting(modelInput, payload.Technical_assets_running) {
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "referenced technical asset does not exist",
			})
			return
		}
		sharedRuntimeInput, ok := populateSharedRuntime(context, payload)
		if !ok {
			return
		}
		if modelInput.Shared_runtimes == nil {
			modelInput.Shared_runtimes = make(map[string]model.InputSharedRuntime)
		}
		modelInput.Shared_runtimes[payload.Title] = sharedRuntimeInput
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Shared Runtime Creation")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "shared runtime created",
				"id":      sharedRuntimeInput.ID,
			})
		}
	}
}

func checkTechnicalAssetsExisting(modelInput model.ModelInput, techAssetIDs []string) (ok bool) {
	for _, techAssetID := range techAssetIDs {
		exists := false
		for _, val := range modelInput.Technical_assets {
			if val.ID == techAssetID {
				exists = true
				break
			}
		}
		if !exists {
			return false
		}
	}
	return true
}

func populateSharedRuntime(context *gin.Context, payload payloadSharedRuntime) (sharedRuntimeInput model.InputSharedRuntime, ok bool) {
	sharedRuntimeInput = model.InputSharedRuntime{
		ID:                       payload.Id,
		Description:              payload.Description,
		Tags:                     support.LowerCaseAndTrim(payload.Tags),
		Technical_assets_running: payload.Technical_assets_running,
	}
	return sharedRuntimeInput, true
}

func deleteSharedRuntime(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.Shared_runtimes {
			if sharedRuntime.ID == context.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				for indivRiskCatTitle, indivRiskCat := range modelInput.Individual_risk_categories {
					if indivRiskCat.Risks_identified != nil {
						for indivRiskInstanceTitle, indivRiskInstance := range indivRiskCat.Risks_identified {
							if indivRiskInstance.Most_relevant_shared_runtime == sharedRuntime.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle]
								x.Most_relevant_shared_runtime = "" // TODO needs more testing
								modelInput.Individual_risk_categories[indivRiskCatTitle].Risks_identified[indivRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.Shared_runtimes, title)
				ok = writeModel(context, key, folderNameOfKey, &modelInput, "Shared Runtime Deletion")
				if ok {
					context.JSON(http.StatusOK, gin.H{
						"message":            "shared runtime deleted",
						"id":                 sharedRuntime.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func createNewDataAsset(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadDataAsset{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.Data_assets[payload.Title]; exists {
			context.JSON(http.StatusConflict, gin.H{
				"error": "data asset with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by it's "id", so do this uniqueness check also
		for _, asset := range modelInput.Data_assets {
			if asset.ID == payload.Id {
				context.JSON(http.StatusConflict, gin.H{
					"error": "data asset with this id already exists",
				})
				return
			}
		}
		dataAssetInput, ok := populateDataAsset(context, payload)
		if !ok {
			return
		}
		if modelInput.Data_assets == nil {
			modelInput.Data_assets = make(map[string]model.InputDataAsset)
		}
		modelInput.Data_assets[payload.Title] = dataAssetInput
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Data Asset Creation")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "data asset created",
				"id":      dataAssetInput.ID,
			})
		}
	}
}

func populateDataAsset(context *gin.Context, payload payloadDataAsset) (dataAssetInput model.InputDataAsset, ok bool) {
	usage, err := model.ParseUsage(payload.Usage)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	quantity, err := model.ParseQuantity(payload.Quantity)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	confidentiality, err := confidentiality.ParseConfidentiality(payload.Confidentiality)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	integrity, err := criticality.ParseCriticality(payload.Integrity)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	availability, err := criticality.ParseCriticality(payload.Availability)
	if err != nil {
		handleErrorInServiceCall(err, context)
		return dataAssetInput, false
	}
	dataAssetInput = model.InputDataAsset{
		ID:                       payload.Id,
		Description:              payload.Description,
		Usage:                    usage.String(),
		Tags:                     support.LowerCaseAndTrim(payload.Tags),
		Origin:                   payload.Origin,
		Owner:                    payload.Owner,
		Quantity:                 quantity.String(),
		Confidentiality:          confidentiality.String(),
		Integrity:                integrity.String(),
		Availability:             availability.String(),
		Justification_cia_rating: payload.Justification_cia_rating,
	}
	return dataAssetInput, true
}

func getDataAssets(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Data_assets)
	}
}

func getTrustBoundaries(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Trust_boundaries)
	}
}

func getSharedRuntimes(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Shared_runtimes)
	}
}

func arrayOfStringValues(values []core.TypeEnum) []string {
	result := make([]string, 0)
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

func getModel(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	_, yamlText, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		tmpResultFile, err := ioutil.TempFile(model.TempFolder, "threagile-*.yaml")
		support.CheckErr(err)
		err = ioutil.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0400)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to stream model file",
			})
			return
		}
		defer os.Remove(tmpResultFile.Name())
		context.FileAttachment(tmpResultFile.Name(), "threagile.yaml")
	}
}

type payloadModels struct {
	ID                 string    `json:"id"`
	Title              string    `json:"title"`
	Timestamp_created  time.Time `json:"timestamp_created"`
	Timestamp_modified time.Time `json:"timestamp_modified"`
}

type payloadCover struct {
	Title  string       `json:"title"`
	Date   time.Time    `json:"date"`
	Author model.Author `json:"author"`
}

type payloadOverview struct {
	Management_summary_comment string         `json:"management_summary_comment"`
	Business_criticality       string         `json:"business_criticality"`
	Business_overview          model.Overview `json:"business_overview"`
	Technical_overview         model.Overview `json:"technical_overview"`
}

type payloadAbuseCases map[string]string

type payloadSecurityRequirements map[string]string

type payloadDataAsset struct {
	Title                    string   `json:"title"`
	Id                       string   `json:"id"`
	Description              string   `json:"description"`
	Usage                    string   `json:"usage"`
	Tags                     []string `json:"tags"`
	Origin                   string   `json:"origin"`
	Owner                    string   `json:"owner"`
	Quantity                 string   `json:"quantity"`
	Confidentiality          string   `json:"confidentiality"`
	Integrity                string   `json:"integrity"`
	Availability             string   `json:"availability"`
	Justification_cia_rating string   `json:"justification_cia_rating"`
}

type payloadSharedRuntime struct {
	Title                    string   `json:"title"`
	Id                       string   `json:"id"`
	Description              string   `json:"description"`
	Tags                     []string `json:"tags"`
	Technical_assets_running []string `json:"technical_assets_running"`
}

func setSecurityRequirements(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSecurityRequirements{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Security_requirements = payload
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Security Requirements Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func getSecurityRequirements(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Security_requirements)
	}
}

func setAbuseCases(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadAbuseCases{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Abuse_cases = payload
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Abuse Cases Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func getAbuseCases(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, model.Abuse_cases)
	}
}

func setOverview(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadOverview{}
		err := context.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		criticality, err := criticality.ParseCriticality(payload.Business_criticality)
		if err != nil {
			handleErrorInServiceCall(err, context)
			return
		}
		modelInput.Management_summary_comment = payload.Management_summary_comment
		modelInput.Business_criticality = criticality.String()
		modelInput.Business_overview.Description = payload.Business_overview.Description
		modelInput.Business_overview.Images = payload.Business_overview.Images
		modelInput.Technical_overview.Description = payload.Technical_overview.Description
		modelInput.Technical_overview.Images = payload.Technical_overview.Images
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Overview Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func handleErrorInServiceCall(err error, context *gin.Context) {
	log.Println(err)
	context.JSON(http.StatusBadRequest, gin.H{
		"error": strings.TrimSpace(err.Error()),
	})
}

func getOverview(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"management_summary_comment": model.Management_summary_comment,
			"business_criticality":       model.Business_criticality,
			"business_overview":          model.Business_overview,
			"technical_overview":         model.Technical_overview,
		})
	}
}

func setCover(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	modelInput, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadCover{}
		err := context.BindJSON(&payload)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Title = payload.Title
		if !payload.Date.IsZero() {
			modelInput.Date = payload.Date.Format("2006-01-02")
		}
		modelInput.Author.Name = payload.Author.Name
		modelInput.Author.Homepage = payload.Author.Homepage
		ok = writeModel(context, key, folderNameOfKey, &modelInput, "Cover Update")
		if ok {
			context.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func getCover(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	model, _, ok := readModel(context, context.Param("model-id"), key, folderNameOfKey)
	if ok {
		context.JSON(http.StatusOK, gin.H{
			"title":  model.Title,
			"date":   model.Date,
			"author": model.Author,
		})
	}
}

// creates a sub-folder (named by a new UUID) inside the token folder
func createNewModel(context *gin.Context) {
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	ok = checkObjectCreationThrottler(context, "MODEL")
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)

	uuid := uuid.New().String()
	err := os.Mkdir(folderNameForModel(folderNameOfKey, uuid), 0700)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create model",
		})
		return
	}

	yaml := `title: New Threat Model
threagile_version: ` + model.ThreagileVersion + `
author:
  name: ""
  homepage: ""
date:
business_overview:
  description: ""
  images: []
technical_overview:
  description: ""
  images: []
business_criticality: ""
management_summary_comment: ""
questions: {}
abuse_cases: {}
security_requirements: {}
tags_available: []
data_assets: {}
technical_assets: {}
trust_boundaries: {}
shared_runtimes: {}
individual_risk_categories: {}
risk_tracking: {}
diagram_tweak_nodesep: ""
diagram_tweak_ranksep: ""
diagram_tweak_edge_layout: ""
diagram_tweak_suppress_edge_labels: false
diagram_tweak_invisible_connections_between_assets: []
diagram_tweak_same_rank_assets: []`

	ok = writeModelYAML(context, yaml, key, folderNameForModel(folderNameOfKey, uuid), "New Model Creation", true)
	if ok {
		context.JSON(http.StatusCreated, gin.H{
			"message": "model created",
			"id":      uuid,
		})
	}
}

func listModels(context *gin.Context) { // TODO currently returns error when any model is no longer valid in syntax, so eventually have some fallback to not just bark on an invalid model...
	folderNameOfKey, key, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)

	result := make([]payloadModels, 0)
	modelFolders, err := ioutil.ReadDir(folderNameOfKey)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	for _, fileInfo := range modelFolders {
		if fileInfo.IsDir() {
			modelStat, err := os.Stat(folderNameOfKey + "/" + fileInfo.Name() + "/threagile.yaml")
			if err != nil {
				log.Println(err)
				context.JSON(http.StatusNotFound, gin.H{
					"error": "unable to list model",
				})
				return
			}
			model, _, ok := readModel(context, fileInfo.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			result = append(result, payloadModels{
				ID:                 fileInfo.Name(),
				Title:              model.Title,
				Timestamp_created:  fileInfo.ModTime(),
				Timestamp_modified: modelStat.ModTime(),
			})
		}
	}
	context.JSON(http.StatusOK, result)
}

func deleteModel(context *gin.Context) {
	folderNameOfKey, _, ok := checkTokenToFolderName(context)
	if !ok {
		return
	}
	lockFolder(folderNameOfKey)
	defer unlockFolder(folderNameOfKey)
	folder, ok := checkModelFolder(context, context.Param("model-id"), folderNameOfKey)
	if ok {
		err := os.RemoveAll(folder)
		if err != nil {
			context.JSON(http.StatusNotFound, gin.H{
				"error": "model not found",
			})
		}
		context.JSON(http.StatusOK, gin.H{
			"message": "model deleted",
		})
	}
}

func checkModelFolder(context *gin.Context, modelUUID string, folderNameOfKey string) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	modelFolder = folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	return modelFolder, true
}

func readModel(context *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult model.ModelInput, yamlText string, ok bool) {
	modelFolder, ok := checkModelFolder(context, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, false
	}
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	fileBytes, err := ioutil.ReadFile(modelFolder + "/threagile.yaml")
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:12]
	ciphertext := fileBytes[12:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	modelInput := model.ModelInput{}
	yamlBytes := buf.Bytes()
	err = yaml.Unmarshal(yamlBytes, &modelInput)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	return modelInput, string(yamlBytes), true
}

func writeModel(context *gin.Context, key []byte, folderNameOfKey string, modelInput *model.ModelInput, changeReasonForHistory string) (ok bool) {
	modelFolder, ok := checkModelFolder(context, context.Param("model-id"), folderNameOfKey)
	if ok {
		modelInput.Threagile_version = model.ThreagileVersion
		yamlBytes, err := yaml.Marshal(modelInput)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
		/*
			yamlBytes = model.ReformatYAML(yamlBytes)
		*/
		return writeModelYAML(context, string(yamlBytes), key, modelFolder, changeReasonForHistory, false)
	}
	return false
}

func writeModelYAML(context *gin.Context, yaml string, key []byte, modelFolder string, changeReasonForHistory string, skipBackup bool) (ok bool) {
	if *verbose {
		fmt.Println("about to write " + strconv.Itoa(len(yaml)) + " bytes of yaml into model folder: " + modelFolder)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(yaml))
	w.Close()
	plaintext := b.Bytes()
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	if !skipBackup {
		err = backupModelToHistory(modelFolder, changeReasonForHistory)
		if err != nil {
			log.Println(err)
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
	}
	f, err := os.Create(modelFolder + "/threagile.yaml")
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	f.Write(nonce)
	f.Write(ciphertext)
	f.Close()
	return true
}

func backupModelToHistory(modelFolder string, changeReasonForHistory string) (err error) {
	historyFolder := modelFolder + "/history"
	if _, err := os.Stat(historyFolder); os.IsNotExist(err) {
		err = os.Mkdir(historyFolder, 0700)
		if err != nil {
			return err
		}
	}
	input, err := ioutil.ReadFile(modelFolder + "/threagile.yaml")
	if err != nil {
		return err
	}
	historyFile := historyFolder + "/" + time.Now().Format("2006-01-02 15:04:05") + " " + changeReasonForHistory + ".backup"
	err = ioutil.WriteFile(historyFile, input, 0400)
	if err != nil {
		return err
	}
	// now delete any old files if over limit to keep
	files, err := ioutil.ReadDir(historyFolder)
	if err != nil {
		return err
	}
	if len(files) > backupHistoryFilesToKeep {
		requiredToDelete := len(files) - backupHistoryFilesToKeep
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name() < files[j].Name()
		})
		for _, file := range files {
			requiredToDelete--
			err = os.Remove(historyFolder + "/" + file.Name())
			if err != nil {
				return err
			}
			if requiredToDelete <= 0 {
				break
			}
		}
	}
	return
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func generateKeyFromAlreadyStrongRandomInput(alreadyRandomInput []byte) []byte {
	// Establish the parameters to use for Argon2.
	p := &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   keySize,
	}
	// As the input is already cryptographically secure random, the salt is simply the first n bytes
	salt := alreadyRandomInput[0:p.saltLength]
	hash := argon2.IDKey(alreadyRandomInput[p.saltLength:], salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

func folderNameForModel(folderNameOfKey string, uuid string) string {
	return folderNameOfKey + "/" + uuid
}

var throttlerLock sync.Mutex
var createdObjectsThrottler = make(map[string][]int64)

func checkObjectCreationThrottler(context *gin.Context, typeName string) bool {
	throttlerLock.Lock()
	defer throttlerLock.Unlock()

	// remove all elements older than 3 minutes (= 180000000000 ns)
	now := time.Now().UnixNano()
	cutoff := now - 180000000000
	for keyCheck, _ := range createdObjectsThrottler {
		for i := 0; i < len(createdObjectsThrottler[keyCheck]); i++ {
			if createdObjectsThrottler[keyCheck][i] < cutoff {
				// Remove the element at index i from slice (safe while looping using i as iterator)
				createdObjectsThrottler[keyCheck] = append(createdObjectsThrottler[keyCheck][:i], createdObjectsThrottler[keyCheck][i+1:]...)
				i-- // Since we just deleted a[i], we must redo that index
			}
		}
		length := len(createdObjectsThrottler[keyCheck])
		if length == 0 {
			delete(createdObjectsThrottler, keyCheck)
		}
		/*
			if *verbose {
				log.Println("Throttling count: "+strconv.Itoa(length))
			}
		*/
	}

	// check current request
	keyHash := support.Hash(typeName) // getting the real client ip is not easy inside fully encapsulated containerized runtime
	if _, ok := createdObjectsThrottler[keyHash]; !ok {
		createdObjectsThrottler[keyHash] = make([]int64, 0)
	}
	// check the limit of 20 creations for this type per 3 minutes
	withinLimit := len(createdObjectsThrottler[keyHash]) < 20
	if withinLimit {
		createdObjectsThrottler[keyHash] = append(createdObjectsThrottler[keyHash], now)
		return true
	}
	context.JSON(http.StatusTooManyRequests, gin.H{
		"error": "object creation throttling exceeded (denial-of-service protection): please wait some time and try again",
	})
	return false
}

var locksByFolderName = make(map[string]*sync.Mutex)

func lockFolder(folderName string) {
	globalLock.Lock()
	defer globalLock.Unlock()
	_, exists := locksByFolderName[folderName]
	if !exists {
		locksByFolderName[folderName] = &sync.Mutex{}
	}
	locksByFolderName[folderName].Lock()
}

func unlockFolder(folderName string) {
	if _, exists := locksByFolderName[folderName]; exists {
		locksByFolderName[folderName].Unlock()
		delete(locksByFolderName, folderName)
	}
}

type tokenHeader struct {
	Token string `header:"token"`
}
type keyHeader struct {
	Key string `header:"key"`
}

func folderNameFromKey(key []byte) string {
	sha512Hash := hashSHA256(key)
	return baseFolder + "/" + sha512Hash
}

func hashSHA256(key []byte) string {
	hasher := sha512.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

func createKey(context *gin.Context) {
	ok := checkObjectCreationThrottler(context, "KEY")
	if !ok {
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()

	keyBytesArr := make([]byte, keySize)
	n, err := rand.Read(keyBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	err = os.Mkdir(folderNameFromKey(keyBytesArr), 0700)
	if err != nil {
		log.Println(err)
		context.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	context.JSON(http.StatusCreated, gin.H{
		"key": base64.RawURLEncoding.EncodeToString(keyBytesArr[:]),
	})
}

func checkTokenToFolderName(context *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := tokenHeader{}
	if err := context.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	housekeepingTokenMaps() // to remove timed-out ones
	tokenHash := hashSHA256(token)
	if timeoutStruct, exists := mapTokenHashToTimeoutStruct[tokenHash]; exists {
		// re-create the key from token
		key := xor(token, timeoutStruct.xorRand)
		folderNameOfKey := folderNameFromKey(key)
		if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
			log.Println(err)
			context.JSON(http.StatusNotFound, gin.H{
				"error": "token not found",
			})
			return folderNameOfKey, key, false
		}
		timeoutStruct.lastAcessedNanotime = time.Now().UnixNano()
		return folderNameOfKey, key, true
	} else {
		context.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
}

func checkKeyToFolderName(context *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := keyHeader{}
	if err := context.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Key))
	if len(key) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	folderNameOfKey = folderNameFromKey(key)
	if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
		log.Println(err)
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	return folderNameOfKey, key, true
}

func deleteKey(context *gin.Context) {
	folderName, _, ok := checkKeyToFolderName(context)
	if !ok {
		return
	}
	globalLock.Lock()
	defer globalLock.Unlock()
	err := os.RemoveAll(folderName)
	if err != nil {
		log.Println("error during key delete: " + err.Error())
		context.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"message": "key deleted",
	})
}

func parseCommandlineArgs() {
	modelFilename = flag.String("model", "threagile.yaml", "input model yaml file")
	outputDir = flag.String("output", ".", "output directory")
	raaPlugin = flag.String("raa-plugin", "raa.so", "RAA calculation plugin (.so shared object) file name")
	executeModelMacro = flag.String("execute-model-macro", "", "Execute model macro (by ID)")
	createExampleModel = flag.Bool("create-example-model", false, "just create an example model named threagile-example-model.yaml in the output directory")
	createStubModel = flag.Bool("create-stub-model", false, "just create a minimal stub model named threagile-stub-model.yaml in the output directory")
	createEditingSupport = flag.Bool("create-editing-support", false, "just create some editing support stuff in the output directory")
	serverPort = flag.Int("server", 0, "start a server (instead of commandline execution) on the given port")
	templateFilename = flag.String("background", "background.pdf", "background pdf file")
	generateDataFlowDiagram = flag.Bool("generate-data-flow-diagram", true, "generate data-flow diagram")
	generateDataAssetDiagram = flag.Bool("generate-data-asset-diagram", true, "generate data asset diagram")
	generateRisksJSON = flag.Bool("generate-risks-json", true, "generate risks json")
	generateTechnicalAssetsJSON = flag.Bool("generate-technical-assets-json", true, "generate technical assets json")
	generateStatsJSON = flag.Bool("generate-stats-json", true, "generate stats json")
	generateRisksExcel = flag.Bool("generate-risks-excel", true, "generate risks excel")
	generateTagsExcel = flag.Bool("generate-tags-excel", true, "generate tags excel")
	generateReportPDF = flag.Bool("generate-report-pdf", true, "generate report pdf, including diagrams")
	generateDefectdojoGeneric = flag.Bool("generate-defectdojo-json", true, "generate defectdojo generic json")
	diagramDPI = flag.Int("diagram-dpi", defaultGraphvizDPI, "DPI used to render: maximum is "+strconv.Itoa(maxGraphvizDPI)+"")
	skipRiskRules = flag.String("skip-risk-rules", "", "comma-separated list of risk rules (by their ID) to skip")
	riskRulesPlugins = flag.String("custom-risk-rules-plugins", "", "comma-separated list of plugins (.so shared object) file names with custom risk rules to load")
	verbose = flag.Bool("verbose", false, "verbose output")
	ignoreOrphanedRiskTracking = flag.Bool("ignore-orphaned-risk-tracking", false, "ignore orphaned risk tracking (just log them) not matching a concrete risk")
	version := flag.Bool("version", false, "print version")
	listTypes := flag.Bool("list-types", false, "print type information (enum values to be used in models)")
	listRiskRules := flag.Bool("list-risk-rules", false, "print risk rules")
	listModelMacros := flag.Bool("list-model-macros", false, "print model macros")
	print3rdParty := flag.Bool("print-3rd-party-licenses", false, "print 3rd-party license information")
	license := flag.Bool("print-license", false, "print license information")
	flag.Usage = func() {
		printLogo()
		fmt.Fprintf(os.Stderr, "Usage: threagile [options]")
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println()
		fmt.Println("If you want to create an example model (via docker) as a starting point to learn about Threagile just run: ")
		fmt.Println(" docker run --rm -it " +
			"-v \"$(pwd)\":/app/work " +
			"threagile/threagile " +
			"-create-example-model " +
			"-output /app/work")
		fmt.Println()
		fmt.Println("If you want to create a minimal stub model (via docker) as a starting point for your own model just run: ")
		fmt.Println(" docker run --rm -it " +
			"-v \"$(pwd)\":/app/work " +
			"threagile/threagile " +
			"-create-stub-model " +
			"-output /app/work")
		fmt.Println()
		printExamples()
		fmt.Println()
	}
	flag.Parse()
	if *diagramDPI < 20 {
		*diagramDPI = 20
	} else if *diagramDPI > maxGraphvizDPI {
		*diagramDPI = 300
	}
	if *version {
		printLogo()
		os.Exit(0)
	}
	if *listTypes {
		printLogo()
		fmt.Println("The following types are available (can be extended for custom rules):")
		fmt.Println()
		printTypes("Authentication", model.AuthenticationValues())
		fmt.Println()
		printTypes("Authorization", model.AuthorizationValues())
		fmt.Println()
		printTypes("Confidentiality", confidentiality.ConfidentialityValues())
		fmt.Println()
		printTypes("Criticality (for integrity and availability)", criticality.CriticalityValues())
		fmt.Println()
		printTypes("Data Breach Probability", model.DataBreachProbabilityValues())
		fmt.Println()
		printTypes("Data Format", model.DataFormatValues())
		fmt.Println()
		printTypes("Encryption", model.EncryptionStyleValues())
		fmt.Println()
		printTypes("Protocol", model.ProtocolValues())
		fmt.Println()
		printTypes("Quantity", model.QuantityValues())
		fmt.Println()
		printTypes("Risk Exploitation Impact", model.RiskExploitationImpactValues())
		fmt.Println()
		printTypes("Risk Exploitation Likelihood", model.RiskExploitationLikelihoodValues())
		fmt.Println()
		printTypes("Risk Function", model.RiskFunctionValues())
		fmt.Println()
		printTypes("Risk Severity", model.RiskSeverityValues())
		fmt.Println()
		printTypes("Risk Status", model.RiskStatusValues())
		fmt.Println()
		printTypes("STRIDE", model.STRIDEValues())
		fmt.Println()
		printTypes("Technical Asset Machine", model.TechnicalAssetMachineValues())
		fmt.Println()
		printTypes("Technical Asset Size", model.TechnicalAssetSizeValues())
		fmt.Println()
		printTypes("Technical Asset Technology", model.TechnicalAssetTechnologyValues())
		fmt.Println()
		printTypes("Technical Asset Type", model.TechnicalAssetTypeValues())
		fmt.Println()
		printTypes("Trust Boundary Type", model.TrustBoundaryTypeValues())
		fmt.Println()
		printTypes("Usage", model.UsageValues())
		fmt.Println()
		os.Exit(0)
	}
	if *listModelMacros {
		printLogo()
		fmt.Println("The following model macros are available (can be extended via custom model macros):")
		fmt.Println()
		/* TODO finish plugin stuff
		fmt.Println("Custom model macros:")
		for id, customModelMacro := range customModelMacros {
			fmt.Println(id, "-->", customModelMacro.GetMacroDetails().Title)
		}
		fmt.Println()
		*/
		fmt.Println("----------------------")
		fmt.Println("Built-in model macros:")
		fmt.Println("----------------------")
		fmt.Println(add_build_pipeline.GetMacroDetails().ID, "-->", add_build_pipeline.GetMacroDetails().Title)
		fmt.Println(add_vault.GetMacroDetails().ID, "-->", add_vault.GetMacroDetails().Title)
		fmt.Println(pretty_print.GetMacroDetails().ID, "-->", pretty_print.GetMacroDetails().Title)
		fmt.Println(remove_unused_tags.GetMacroDetails().ID, "-->", remove_unused_tags.GetMacroDetails().Title)
		fmt.Println(seed_risk_tracking.GetMacroDetails().ID, "-->", seed_risk_tracking.GetMacroDetails().Title)
		fmt.Println(seed_tags.GetMacroDetails().ID, "-->", seed_tags.GetMacroDetails().Title)
		fmt.Println()
		os.Exit(0)
	}
	if *listRiskRules {
		printLogo()
		fmt.Println("The following risk rules are available (can be extended via custom risk rules):")
		fmt.Println()
		loadRiskRulePlugins()
		for _, riskRule := range builtinRiskRulesPlugins {
			fmt.Println(riskRule.Category().Id, "-->", riskRule.Category().Title, "--> with tags:", riskRule.SupportedTags())
		}
		fmt.Println()
		os.Exit(0)
	}
	if *print3rdParty {
		printLogo()
		fmt.Println("Kudos & Credits to the following open-source projects:")
		fmt.Println(" - golang (Google Go License): https://golang.org/LICENSE")
		fmt.Println(" - go-yaml (MIT License): https://github.com/go-yaml/yaml/blob/v3/LICENSE")
		fmt.Println(" - graphviz (CPL License): https://graphviz.gitlab.io/license/")
		fmt.Println(" - gofpdf (MIT License): https://github.com/jung-kurt/gofpdf/blob/master/LICENSE")
		fmt.Println(" - go-chart (MIT License): https://github.com/wcharczuk/go-chart/blob/master/LICENSE")
		fmt.Println(" - excelize (BSD License): https://github.com/qax-os/excelize/blob/master/LICENSE")
		fmt.Println(" - graphics-go (BSD License): https://github.com/BurntSushi/graphics-go/blob/master/LICENSE")
		fmt.Println(" - google-uuid (BSD License): https://github.com/google/uuid/blob/master/LICENSE")
		fmt.Println(" - gin-gonic (MIT License): https://github.com/gin-gonic/gin/blob/master/LICENSE")
		fmt.Println(" - swagger-ui (Apache License): https://swagger.io/license/")
		fmt.Println()
		os.Exit(0)
	}
	if *license {
		printLogo()
		content, err := ioutil.ReadFile("/app/LICENSE.txt")
		support.CheckErr(err)
		fmt.Print(string(content))
		fmt.Println()
		os.Exit(0)
	}
	if *createExampleModel {
		createExampleModelFile()
		printLogo()
		fmt.Println("An example model was created named threagile-example-model.yaml in the output directory.")
		fmt.Println()
		printExamples()
		fmt.Println()
		os.Exit(0)
	}
	if *createStubModel {
		createStubModelFile()
		printLogo()
		fmt.Println("A minimal stub model was created named threagile-stub-model.yaml in the output directory.")
		fmt.Println()
		printExamples()
		fmt.Println()
		os.Exit(0)
	}
	if *createEditingSupport {
		createEditingSupportFiles()
		printLogo()
		fmt.Println("The following files were created in the output directory:")
		fmt.Println(" - schema.json")
		fmt.Println(" - live-templates.txt")
		fmt.Println()
		fmt.Println("For a perfect editing experience within your IDE of choice you can easily get " +
			"model syntax validation and autocompletion (very handy for enum values) as well as live templates: " +
			"Just import the schema.json into your IDE and assign it as \"schema\" to each Threagile YAML file. " +
			"Also try to import individual parts from the live-templates.txt file into your IDE as live editing templates.")
		fmt.Println()
		os.Exit(0)
	}
}

func printLogo() {
	fmt.Println()
	fmt.Println("  _____ _                          _ _      \n |_   _| |__  _ __ ___  __ _  __ _(_) | ___ \n   | | | '_ \\| '__/ _ \\/ _` |/ _` | | |/ _ \\\n   | | | | | | | |  __/ (_| | (_| | | |  __/\n   |_| |_| |_|_|  \\___|\\__,_|\\__, |_|_|\\___|\n                             |___/        ")
	fmt.Println("Threagile - Agile Threat Modeling")
	fmt.Println()
	fmt.Println()
	printVersion()
}

func printVersion() {
	fmt.Println("Documentation: https://threagile.io")
	fmt.Println("Docker Images: https://github.com/Otyg/threagile/pkgs/container/threagile")
	fmt.Println("Sourcecode: https://github.com/otyg/threagile")
	fmt.Println("License: Open-Source (MIT License)")
	fmt.Println("Version: " + model.ThreagileVersion + " (" + buildTimestamp + ")")
	fmt.Println()
	fmt.Println()
}

func createExampleModelFile() {
	support.CopyFile("/app/threagile-example-model.yaml", *outputDir+"/threagile-example-model.yaml")
}

func createStubModelFile() {
	stub, err := ioutil.ReadFile("/app/threagile-stub-model.yaml")
	support.CheckErr(err)
	err = ioutil.WriteFile(*outputDir+"/threagile-stub-model.yaml", addSupportedTags(stub), 0644)
	support.CheckErr(err)
}

func createEditingSupportFiles() {
	support.CopyFile("/app/schema.json", *outputDir+"/schema.json")
	support.CopyFile("/app/live-templates.txt", *outputDir+"/live-templates.txt")
}

func printExamples() {
	fmt.Println("If you want to execute Threagile on a model yaml file (via docker): ")
	fmt.Println(" docker run --rm -it " +
		"-v \"$(pwd)\":/app/work " +
		"threagile/threagile " +
		"-verbose " +
		"-model /app/work/threagile.yaml " +
		"-output /app/work")
	fmt.Println()
	fmt.Println("If you want to run Threagile as a server (REST API) on some port (here 8080): ")
	fmt.Println(" docker run --rm -it " +
		"--shm-size=256m " +
		"-p 8080:8080 " +
		"--name threagile-server " +
		"--mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' " +
		"threagile/threagile -server 8080")
	fmt.Println()
	fmt.Println("If you want to find out about the different enum values usable in the model yaml file: ")
	fmt.Println(" docker run --rm -it threagile/threagile -list-types")
	fmt.Println()
	fmt.Println("If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your favourite IDE: ")
	fmt.Println(" docker run --rm -it -v \"$(pwd)\":/app/work threagile/threagile -create-editing-support -output /app/work")
	fmt.Println()
	fmt.Println("If you want to list all available model macros (which are macros capable of reading a model yaml file, asking you questions in a wizard-style and then update the model yaml file accordingly): ")
	fmt.Println(" docker run --rm -it threagile/threagile -list-model-macros")
	fmt.Println()
	fmt.Println("If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline): ")
	fmt.Println(" docker run --rm -it -v \"$(pwd)\":/app/work threagile/threagile -model /app/work/threagile.yaml -output /app/work -execute-model-macro add-build-pipeline")
}

func printTypes(title string, value interface{}) {
	fmt.Println(fmt.Sprintf("  %v: %v", title, value))
}

func parseModel(inputFilename string) {
	if *verbose {
		fmt.Println("Parsing model:", inputFilename)
	}
	modelYaml, err := ioutil.ReadFile(inputFilename)
	support.CheckErr(err)
	var validatorYaml interface{}
	support.CheckErr(err)
	err = yaml.Unmarshal([]byte(modelYaml), &validatorYaml)
	support.CheckErr(err)
	validatorYaml, err = support.ToStringKeys(validatorYaml)
	support.CheckErr(err)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertContent = true
	compiler.AssertFormat = true
	schemaFile, err := ioutil.ReadFile("schema.json")
	support.CheckErr(err)
	if err := compiler.AddResource("schema.json", strings.NewReader(string(schemaFile))); err != nil {
		panic(err)
	}
	schema, err := compiler.Compile("schema.json")
	if err != nil {
		panic(err)
	}
	if err := schema.Validate(validatorYaml); err != nil {
		panic(err)
	}
	model.ParsedModelRoot = model.ParseModel(modelYaml, deferredRiskTrackingDueToWildcardMatching)
}

func applyWildcardRiskTrackingEvaluation() {
	if *verbose {
		fmt.Println("Executing risk tracking evaluation")
	}
	for syntheticRiskIdPattern, riskTracking := range deferredRiskTrackingDueToWildcardMatching {
		foundSome := false
		var matchingRiskIdExpression = regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(syntheticRiskIdPattern), `\*`, `[^@]+`))
		for syntheticRiskId, _ := range model.GeneratedRisksBySyntheticId {
			if matchingRiskIdExpression.Match([]byte(syntheticRiskId)) && hasNotYetAnyDirectNonWildcardRiskTrackings(syntheticRiskId) {
				foundSome = true
				model.ParsedModelRoot.RiskTracking[syntheticRiskId] = model.RiskTracking{
					SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
					Justification:   riskTracking.Justification,
					CheckedBy:       riskTracking.CheckedBy,
					Ticket:          riskTracking.Ticket,
					Status:          riskTracking.Status,
					Date:            riskTracking.Date,
				}
			}
		}
		if !foundSome {
			if *ignoreOrphanedRiskTracking {
				fmt.Println("Wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern)
			} else {
				panic(errors.New("wildcard risk tracking does not match any risk id: " + syntheticRiskIdPattern))
			}
		}
	}
}

func hasNotYetAnyDirectNonWildcardRiskTrackings(syntheticRiskId string) bool {
	if _, ok := model.ParsedModelRoot.RiskTracking[syntheticRiskId]; ok {
		return false
	}
	return true
}

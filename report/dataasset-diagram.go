package report

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/otyg/threagile/colors"
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/support"
)

const graphvizDataAssetDiagramConversionCall = "render-data-asset-diagram.sh"
const dataAssetDiagramFilenamePNG = "data-asset-diagram.png"

func RenderDataAssetDiagram(outputDirectory string, dataAssetDiagramFilenameDOT string, keepDiagramSourceFiles bool, diagramDPI *int, verbose *bool) {
	gvFile := outputDirectory + "/" + dataAssetDiagramFilenameDOT
	if !keepDiagramSourceFiles {
		tmpFile, err := ioutil.TempFile(model.TempFolder, dataAssetDiagramFilenameDOT)
		support.CheckErr(err)
		gvFile = tmpFile.Name()
		defer os.Remove(gvFile)
	}
	dotFile := WriteDataAssetDiagramGraphvizDOT(gvFile, *diagramDPI, verbose)
	RenderDataAssetDiagramGraphvizImage(dotFile, outputDirectory, verbose)
}
func WriteDataAssetDiagramGraphvizDOT(diagramFilenameDOT string, dpi int, verbose *bool) *os.File {
	if *verbose {
		fmt.Println("Writing data asset diagram input")
	}
	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=true \n")

	// Metadata init ===============================================================================
	dotContent.WriteString(`	graph [
		dpi=` + strconv.Itoa(dpi) + `
		fontname="Verdana"
		labelloc="c"
		fontsize="20"
		splines=false
		rankdir="LR"
		nodesep=1.0
		ranksep=3.0
        outputorder="nodesfirst"
	];
	node [
		fontcolor="white"
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Technical Assets ===============================================================================
	techAssets := make([]model.TechnicalAsset, 0)
	for _, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(model.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		if len(technicalAsset.DataAssetsStored) > 0 || len(technicalAsset.DataAssetsProcessed) > 0 {
			dotContent.WriteString(MakeTechAssetNode(technicalAsset, true))
			dotContent.WriteString("\n")
		}
	}

	// Data Assets ===============================================================================
	dataAssets := make([]model.DataAsset, 0)
	for _, dataAsset := range model.ParsedModelRoot.DataAssets {
		dataAssets = append(dataAssets, dataAsset)
	}
	sort.Sort(model.ByDataAssetDataBreachProbabilityAndTitleSort(dataAssets))
	for _, dataAsset := range dataAssets {
		dotContent.WriteString(makeDataAssetNode(dataAsset))
		dotContent.WriteString("\n")
	}

	// Data Asset to Tech Asset links ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, sourceId := range technicalAsset.DataAssetsStored {
			targetId := technicalAsset.Id
			dotContent.WriteString("\n")
			dotContent.WriteString(support.Hash(sourceId) + " -> " + support.Hash(targetId) +
				` [ color="blue" style="solid" ];`)
			dotContent.WriteString("\n")
		}
		for _, sourceId := range technicalAsset.DataAssetsProcessed {
			if !model.Contains(technicalAsset.DataAssetsStored, sourceId) { // here only if not already drawn above
				targetId := technicalAsset.Id
				dotContent.WriteString("\n")
				dotContent.WriteString(support.Hash(sourceId) + " -> " + support.Hash(targetId) +
					` [ color="#666666" style="dashed" ];`)
				dotContent.WriteString("\n")
			}
		}
	}

	dotContent.WriteString("}")

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	support.CheckErr(err)
	defer file.Close()
	_, err = fmt.Fprintln(file, dotContent.String())
	support.CheckErr(err)
	return file
}

func makeDataAssetNode(dataAsset model.DataAsset) string {
	var color string
	switch dataAsset.IdentifiedDataBreachProbabilityStillAtRisk() {
	case model.Probable:
		color = colors.RgbHexColorHighRisk()
	case model.Possible:
		color = colors.RgbHexColorMediumRisk()
	case model.Improbable:
		color = colors.RgbHexColorLowRisk()
	default:
		color = "#444444" // since black is too dark here as fill color
	}
	if !dataAsset.IsDataBreachPotentialStillAtRisk() {
		color = "#444444" // since black is too dark here as fill color
	}
	return "  " + support.Hash(dataAsset.Id) + ` [ label=<<b>` + support.Encode(dataAsset.Title) + `</b>> penwidth="3.0" style="filled" fillcolor="` + color + `" color="` + color + "\"\n  ]; "
}

func RenderDataAssetDiagramGraphvizImage(dotFile *os.File, targetDir string, verbose *bool) { // TODO dedupe with other render...() method here
	if *verbose {
		fmt.Println("Rendering data asset diagram input")
	}
	// tmp files
	tmpFileDOT, err := ioutil.TempFile(model.TempFolder, "diagram-*-.gv")
	support.CheckErr(err)
	defer os.Remove(tmpFileDOT.Name())

	tmpFilePNG, err := ioutil.TempFile(model.TempFolder, "diagram-*-.png")
	support.CheckErr(err)
	defer os.Remove(tmpFilePNG.Name())

	// copy into tmp file as input
	input, err := ioutil.ReadFile(dotFile.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(tmpFileDOT.Name(), input, 0644)
	if err != nil {
		fmt.Println("Error creating", tmpFileDOT.Name())
		fmt.Println(err)
		return
	}

	// exec
	cmd := exec.Command(graphvizDataAssetDiagramConversionCall, tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error: " + err.Error()))
	}
	// copy into resulting file
	input, err = ioutil.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(targetDir+"/"+dataAssetDiagramFilenamePNG, input, 0644)
	if err != nil {
		fmt.Println("Error creating", dataAssetDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}

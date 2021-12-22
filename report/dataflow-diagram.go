package report

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/otyg/threagile/colors"
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/support"
)

const dataFlowDiagramFilenameDOT = "data-flow-diagram.gv"
const dataFlowDiagramFilenamePNG = "data-flow-diagram.png"
const graphvizDataFlowDiagramConversionCall = "render-data-flow-diagram.sh"

func RenderDataFlowDiagram(outputDirectory string, keepDiagramSourceFiles bool, diagramDPI *int, verbose *bool) {
	gvFile := outputDirectory + "/" + dataFlowDiagramFilenameDOT
	if !keepDiagramSourceFiles {
		tmpFileGV, err := ioutil.TempFile(model.TempFolder, dataFlowDiagramFilenameDOT)
		support.CheckErr(err)
		gvFile = tmpFileGV.Name()
		defer os.Remove(gvFile)
	}
	dotFile := writeDataFlowDiagramGraphvizDOT(gvFile, *diagramDPI, verbose)
	renderDataFlowDiagramGraphvizImage(dotFile, outputDirectory, verbose)
}

func writeDataFlowDiagramGraphvizDOT(diagramFilenameDOT string, dpi int, verbose *bool) *os.File {
	if *verbose {
		fmt.Println("Writing data flow diagram input")
	}
	var dotContent strings.Builder
	drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks := true

	dotContent.WriteString("digraph generatedModel { concentrate=false \n")

	// Metadata init ===============================================================================
	tweaks := ""
	if model.ParsedModelRoot.DiagramTweakNodesep > 0 {
		tweaks += "\n		nodesep=\"" + strconv.Itoa(model.ParsedModelRoot.DiagramTweakNodesep) + "\""
	}
	if model.ParsedModelRoot.DiagramTweakRanksep > 0 {
		tweaks += "\n		ranksep=\"" + strconv.Itoa(model.ParsedModelRoot.DiagramTweakRanksep) + "\""
	}
	suppressBidirectionalArrows := true
	splines := "ortho"
	if len(model.ParsedModelRoot.DiagramTweakEdgeLayout) > 0 {
		switch model.ParsedModelRoot.DiagramTweakEdgeLayout {
		case "spline":
			splines = "spline"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "polyline":
			splines = "polyline"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "ortho":
			splines = "ortho"
			suppressBidirectionalArrows = true
		case "curved":
			splines = "curved"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "false":
			splines = "false"
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		default:
			panic(errors.New("unknown value for diagram_tweak_suppress_edge_labels (spline, polyline, ortho, curved, false): " +
				model.ParsedModelRoot.DiagramTweakEdgeLayout))
		}
	}
	rankdir := "TB"
	if model.ParsedModelRoot.DiagramTweakLayoutLeftToRight {
		rankdir = "LR"
	}
	modelTitle := ""
	addModelTitle := false
	if addModelTitle {
		modelTitle = `label="` + model.ParsedModelRoot.Title + `"`
	}
	dotContent.WriteString(`	graph [ ` + modelTitle + `
		labelloc=t
		fontname="Verdana"
		fontsize=40
        outputorder="nodesfirst"
		dpi=` + strconv.Itoa(dpi) + `
		splines=` + splines + `
		rankdir="` + rankdir + `"
` + tweaks + `
	];
	node [
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Trust Boundaries ===============================================================================
	var subgraphSnippetsById = make(map[string]string)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0)
	for k, _ := range model.ParsedModelRoot.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		trustBoundary := model.ParsedModelRoot.TrustBoundaries[key]
		var snippet strings.Builder
		if len(trustBoundary.TechnicalAssetsInside) > 0 || len(trustBoundary.TrustBoundariesNested) > 0 {
			if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				// see https://stackoverflow.com/questions/17247455/how-do-i-add-extra-space-between-clusters?noredirect=1&lq=1
				snippet.WriteString("\n subgraph cluster_space_boundary_for_layout_only_1" + support.Hash(trustBoundary.Id) + " {\n")
				snippet.WriteString(`	graph [
                                              dpi=` + strconv.Itoa(dpi) + `
											  label=<<table border="0" cellborder="0" cellpadding="0" bgcolor="#FFFFFF55"><tr><td><b> </b></td></tr></table>>
											  fontsize="21"
											  style="invis"
											  color="green"
											  fontcolor="green"
											  margin="50.0"
											  penwidth="6.5"
                                              outputorder="nodesfirst"
											];`)
			}
			snippet.WriteString("\n subgraph cluster_" + support.Hash(trustBoundary.Id) + " {\n")
			color, fontColor, bgColor, style, fontname := colors.RgbHexColorTwilight(), colors.RgbHexColorTwilight() /*"#550E0C"*/, "#FAFAFA", "dashed", "Verdana"
			penwidth := 4.5
			if len(trustBoundary.TrustBoundariesNested) > 0 {
				//color, fontColor, style, fontname = colors.Blue, colors.Blue, "dashed", "Verdana"
				penwidth = 5.5
			}
			if len(trustBoundary.ParentTrustBoundaryID()) > 0 {
				bgColor = "#F1F1F1"
			}
			if trustBoundary.Type == model.NetworkPolicyNamespaceIsolation {
				fontColor, bgColor = "#222222", "#DFF4FF"
			}
			if trustBoundary.Type == model.ExecutionEnvironment {
				fontColor, bgColor, style = "#555555", "#FFFFF0", "dotted"
			}
			snippet.WriteString(`	graph [
      dpi=` + strconv.Itoa(dpi) + `
      label=<<table border="0" cellborder="0" cellpadding="0"><tr><td><b>` + trustBoundary.Title + `</b> (` + trustBoundary.Type.String() + `)</td></tr></table>>
      fontsize="21"
      style="` + style + `"
      color="` + color + `"
      bgcolor="` + bgColor + `"
      fontcolor="` + fontColor + `"
      fontname="` + fontname + `"
      penwidth="` + fmt.Sprintf("%f", penwidth) + `"
      forcelabels=true
      outputorder="nodesfirst"
	  margin="50.0"
    ];`)
			snippet.WriteString("\n")
			keys := trustBoundary.TechnicalAssetsInside
			sort.Strings(keys)
			for _, technicalAssetInside := range keys {
				//log.Println("About to add technical asset link to trust boundary: ", technicalAssetInside)
				technicalAsset := model.ParsedModelRoot.TechnicalAssets[technicalAssetInside]
				snippet.WriteString(support.Hash(technicalAsset.Id))
				snippet.WriteString(";\n")
			}
			keys = trustBoundary.TrustBoundariesNested
			sort.Strings(keys)
			for _, trustBoundaryNested := range keys {
				//log.Println("About to add nested trust boundary to trust boundary: ", trustBoundaryNested)
				trustBoundaryNested := model.ParsedModelRoot.TrustBoundaries[trustBoundaryNested]
				snippet.WriteString("LINK-NEEDS-REPLACED-BY-cluster_" + support.Hash(trustBoundaryNested.Id))
				snippet.WriteString(";\n")
			}
			snippet.WriteString(" }\n\n")
			if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
				snippet.WriteString(" }\n\n")
			}
		}
		subgraphSnippetsById[support.Hash(trustBoundary.Id)] = snippet.String()
	}
	// here replace links and remove from map after replacement (i.e. move snippet into nested)
	for i, _ := range subgraphSnippetsById {
		re := regexp.MustCompile(`LINK-NEEDS-REPLACED-BY-cluster_([0-9]*);`)
		for {
			matches := re.FindStringSubmatch(subgraphSnippetsById[i])
			if len(matches) > 0 {
				embeddedSnippet := " //nested:" + subgraphSnippetsById[matches[1]]
				subgraphSnippetsById[i] = strings.ReplaceAll(subgraphSnippetsById[i], matches[0], embeddedSnippet)
				subgraphSnippetsById[matches[1]] = "" // to something like remove it
			} else {
				break
			}
		}
	}
	// now write them all
	keys = make([]string, 0)
	for k, _ := range subgraphSnippetsById {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		snippet := subgraphSnippetsById[key]
		dotContent.WriteString(snippet)
	}

	// Technical Assets ===============================================================================
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	// Convert map to slice of values:
	techAssets := []model.TechnicalAsset{}
	for _, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(model.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		dotContent.WriteString(MakeTechAssetNode(technicalAsset, false))
		dotContent.WriteString("\n")
	}

	// Data Flows (Technical Communication Links) ===============================================================================
	for _, technicalAsset := range techAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			sourceId := technicalAsset.Id
			targetId := dataFlow.TargetId
			//log.Println("About to add link from", sourceId, "to", targetId, "with id", dataFlow.Id)
			var arrowStyle, arrowColor, readOrWriteHead, readOrWriteTail string
			if dataFlow.Readonly {
				readOrWriteHead = "empty"
				readOrWriteTail = "odot"
			} else {
				readOrWriteHead = "normal"
				readOrWriteTail = "dot"
			}
			dir := "forward"
			if dataFlow.IsBidirectional() {
				if !suppressBidirectionalArrows { // as it does not work as bug in grahviz with ortho: https://gitlab.com/graphviz/graphviz/issues/144
					dir = "both"
				}
			}
			arrowStyle = ` style="` + dataFlow.DetermineArrowLineStyle() + `" penwidth="` + dataFlow.DetermineArrowPenWidth() + `" arrowtail="` + readOrWriteTail + `" arrowhead="` + readOrWriteHead + `" dir="` + dir + `" arrowsize="2.0" `
			arrowColor = ` color="` + dataFlow.DetermineArrowColor() + `"`
			tweaks := ""
			if dataFlow.DiagramTweakWeight > 0 {
				tweaks += " weight=\"" + strconv.Itoa(dataFlow.DiagramTweakWeight) + "\" "
			}

			dotContent.WriteString("\n")
			dotContent.WriteString("  " + support.Hash(sourceId) + " -> " + support.Hash(targetId) +
				` [` + arrowColor + ` ` + arrowStyle + tweaks + ` constraint=` + strconv.FormatBool(dataFlow.DiagramTweakConstraint) + ` `)
			if !model.ParsedModelRoot.DiagramTweakSuppressEdgeLabels {
				dotContent.WriteString(` xlabel="` + support.Encode(dataFlow.Protocol.String()) + `" fontcolor="` + dataFlow.DetermineLabelColor() + `" `)
			}
			dotContent.WriteString(" ];\n")
		}
	}

	dotContent.WriteString(makeDiagramInvisibleConnectionsTweaks())
	dotContent.WriteString(makeDiagramSameRankNodeTweaks())

	dotContent.WriteString("}")

	//fmt.Println(dotContent.String())

	// Write the DOT file
	file, err := os.Create(diagramFilenameDOT)
	support.CheckErr(err)
	defer file.Close()
	_, err = fmt.Fprintln(file, dotContent.String())
	support.CheckErr(err)
	return file
}

func MakeTechAssetNode(technicalAsset model.TechnicalAsset, simplified bool) string {
	if simplified {
		color := colors.RgbHexColorOutOfScope()
		if !technicalAsset.OutOfScope {
			risks := technicalAsset.GeneratedRisks()
			switch model.HighestSeverityStillAtRisk(risks) {
			case model.CriticalSeverity:
				color = colors.RgbHexColorCriticalRisk()
			case model.HighSeverity:
				color = colors.RgbHexColorHighRisk()
			case model.ElevatedSeverity:
				color = colors.RgbHexColorElevatedRisk()
			case model.MediumSeverity:
				color = colors.RgbHexColorMediumRisk()
			case model.LowSeverity:
				color = colors.RgbHexColorLowRisk()
			default:
				color = "#444444" // since black is too dark here as fill color
			}
			if len(model.ReduceToOnlyStillAtRisk(risks)) == 0 {
				color = "#444444" // since black is too dark here as fill color
			}
		}
		return "  " + support.Hash(technicalAsset.Id) + ` [ shape="box" style="filled" fillcolor="` + color + `" 
				label=<<b>` + support.Encode(technicalAsset.Title) + `</b>> penwidth="3.0" color="` + color + `" ];
				`
	} else {
		var shape, title string
		var lineBreak = ""
		switch technicalAsset.Type {
		case model.ExternalEntity:
			shape = "box"
			title = technicalAsset.Title
		case model.Process:
			shape = "ellipse"
			title = technicalAsset.Title
		case model.Datastore:
			shape = "cylinder"
			title = technicalAsset.Title
			if technicalAsset.Redundant {
				lineBreak = "<br/>"
			}
		}

		if technicalAsset.UsedAsClientByHuman {
			shape = "octagon"
		}

		// RAA = Relative Attacker Attractiveness
		raa := technicalAsset.RAA
		var attackerAttractivenessLabel string
		if technicalAsset.OutOfScope {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: out of scope</font>"
		} else {
			attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: " + fmt.Sprintf("%.0f", raa) + " %</font>"
		}

		compartmentBorder := "0"
		if technicalAsset.MultiTenant {
			compartmentBorder = "1"
		}

		return "  " + support.Hash(technicalAsset.Id) + ` [
	label=<<table border="0" cellborder="` + compartmentBorder + `" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + colors.DarkBlue + `">` + lineBreak + technicalAsset.Technology.String() + `</font><br/><font point-size="15" color="` + colors.LightGray + `">` + technicalAsset.Size.String() + `</font></td></tr><tr><td><b><font color="` + technicalAsset.DetermineLabelColor() + `">` + support.Encode(title) + `</font></b><br/></td></tr><tr><td>` + attackerAttractivenessLabel + `</td></tr></table>>
	shape=` + shape + ` style="` + technicalAsset.DetermineShapeBorderLineStyle() + `,` + technicalAsset.DetermineShapeStyle() + `" penwidth="` + technicalAsset.DetermineShapeBorderPenWidth() + `" fillcolor="` + technicalAsset.DetermineShapeFillColor() + `" 
	peripheries=` + strconv.Itoa(technicalAsset.DetermineShapePeripheries()) + `
	color="` + technicalAsset.DetermineShapeBorderColor() + "\"\n  ]; "
	}
}

func makeDiagramInvisibleConnectionsTweaks() string {
	// see https://stackoverflow.com/questions/2476575/how-to-control-node-placement-in-graphviz-i-e-avoid-edge-crossings
	tweak := ""
	if len(model.ParsedModelRoot.DiagramTweakInvisibleConnectionsBetweenAssets) > 0 {
		for _, invisibleConnections := range model.ParsedModelRoot.DiagramTweakInvisibleConnectionsBetweenAssets {
			assetIDs := strings.Split(invisibleConnections, ":")
			if len(assetIDs) == 2 {
				model.CheckTechnicalAssetExists(assetIDs[0], "diagram tweak connections", true)
				model.CheckTechnicalAssetExists(assetIDs[1], "diagram tweak connections", true)
				tweak += "\n" + support.Hash(assetIDs[0]) + " -> " + support.Hash(assetIDs[1]) + " [style=invis]; \n"
			}
		}
	}
	return tweak
}

func makeDiagramSameRankNodeTweaks() string {
	// see https://stackoverflow.com/questions/25734244/how-do-i-place-nodes-on-the-same-level-in-dot
	tweak := ""
	if len(model.ParsedModelRoot.DiagramTweakSameRankAssets) > 0 {
		for _, sameRank := range model.ParsedModelRoot.DiagramTweakSameRankAssets {
			assetIDs := strings.Split(sameRank, ":")
			if len(assetIDs) > 0 {
				tweak += "{ rank=same; "
				for _, id := range assetIDs {
					model.CheckTechnicalAssetExists(id, "diagram tweak same-rank", true)
					if len(model.ParsedModelRoot.TechnicalAssets[id].GetTrustBoundaryId()) > 0 {
						panic(errors.New("technical assets (referenced in same rank diagram tweak) are inside trust boundaries: " +
							fmt.Sprintf("%v", model.ParsedModelRoot.DiagramTweakSameRankAssets)))
					}
					tweak += " " + support.Hash(id) + "; "
				}
				tweak += " }"
			}
		}
	}
	return tweak
}

func renderDataFlowDiagramGraphvizImage(dotFile *os.File, targetDir string, verbose *bool) {
	if *verbose {
		fmt.Println("Rendering data flow diagram input")
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
	cmd := exec.Command(graphvizDataFlowDiagramConversionCall, tmpFileDOT.Name(), tmpFilePNG.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(errors.New("graph rendering call failed with error:" + err.Error()))
	}
	// copy into resulting file
	input, err = ioutil.ReadFile(tmpFilePNG.Name())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(targetDir+"/"+dataFlowDiagramFilenamePNG, input, 0644)
	if err != nil {
		fmt.Println("Error creating", dataFlowDiagramFilenamePNG)
		fmt.Println(err)
		return
	}
}

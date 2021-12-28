package model

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/otyg/threagile/model/confidentiality"
	"github.com/otyg/threagile/model/criticality"
	"github.com/otyg/threagile/support"
	"gopkg.in/yaml.v2"
)

func ParseModel(modelYaml []byte, deferredRiskTrackingDueToWildcardMatching map[string]RiskTracking) ParsedModel {
	modelInput := ModelInput{}
	var error error = yaml.Unmarshal(modelYaml, &modelInput)
	support.CheckErr(error)
	//fmt.Println(modelInput)
	// Add check for threagile-version of model
	var businessCriticality, err = criticality.ParseCriticality(modelInput.Business_criticality)
	support.CheckErr(err)

	reportDate := time.Now()
	if len(modelInput.Date) > 0 {
		reportDate, err = time.Parse("2006-01-02", modelInput.Date)
		if err != nil {
			panic(errors.New("unable to parse 'date' value of model file"))
		}
	}

	ParsedModelRoot = ParsedModel{
		Author:                         modelInput.Author,
		Title:                          modelInput.Title,
		Date:                           reportDate,
		ManagementSummaryComment:       modelInput.Management_summary_comment,
		BusinessCriticality:            businessCriticality,
		BusinessOverview:               removePathElementsFromImageFiles(modelInput.Business_overview),
		TechnicalOverview:              removePathElementsFromImageFiles(modelInput.Technical_overview),
		Questions:                      modelInput.Questions,
		AbuseCases:                     modelInput.Abuse_cases,
		SecurityRequirements:           modelInput.Security_requirements,
		TagsAvailable:                  support.LowerCaseAndTrim(modelInput.Tags_available),
		DiagramTweakNodesep:            modelInput.Diagram_tweak_nodesep,
		DiagramTweakRanksep:            modelInput.Diagram_tweak_ranksep,
		DiagramTweakEdgeLayout:         modelInput.Diagram_tweak_edge_layout,
		DiagramTweakSuppressEdgeLabels: modelInput.Diagram_tweak_suppress_edge_labels,
		DiagramTweakLayoutLeftToRight:  modelInput.Diagram_tweak_layout_left_to_right,
		DiagramTweakInvisibleConnectionsBetweenAssets: modelInput.Diagram_tweak_invisible_connections_between_assets,
		DiagramTweakSameRankAssets:                    modelInput.Diagram_tweak_same_rank_assets,
	}
	if ParsedModelRoot.DiagramTweakNodesep == 0 {
		ParsedModelRoot.DiagramTweakNodesep = 2
	}
	if ParsedModelRoot.DiagramTweakRanksep == 0 {
		ParsedModelRoot.DiagramTweakRanksep = 2
	}

	// Data Assets ===============================================================================
	ParsedModelRoot.DataAssets = make(map[string]DataAsset)
	for title, asset := range modelInput.Data_assets {
		id := fmt.Sprintf("%v", asset.ID)

		usage, err := ParseUsage(asset.Usage)
		support.CheckErr(err)
		quantity, err := ParseQuantity(asset.Quantity)
		support.CheckErr(err)

		confidentiality, err := confidentiality.ParseConfidentiality(asset.Confidentiality)
		support.CheckErr(err)
		integrity, err := criticality.ParseCriticality(asset.Integrity)
		support.CheckErr(err)

		availability, err := criticality.ParseCriticality(asset.Availability)
		support.CheckErr(err)

		support.CheckIdSyntax(id)
		if _, exists := ParsedModelRoot.DataAssets[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		ParsedModelRoot.DataAssets[id] = DataAsset{
			Id:                     id,
			Title:                  title,
			Usage:                  usage,
			Description:            withDefault(fmt.Sprintf("%v", asset.Description), title),
			Quantity:               quantity,
			Tags:                   checkTags(support.LowerCaseAndTrim(asset.Tags), "data asset '"+title+"'"),
			Origin:                 fmt.Sprintf("%v", asset.Origin),
			Owner:                  fmt.Sprintf("%v", asset.Owner),
			Confidentiality:        confidentiality,
			Integrity:              integrity,
			Availability:           availability,
			JustificationCiaRating: fmt.Sprintf("%v", asset.Justification_cia_rating),
		}
	}

	// Technical Assets ===============================================================================
	ParsedModelRoot.TechnicalAssets = make(map[string]TechnicalAsset)
	for title, asset := range modelInput.Technical_assets {
		id := fmt.Sprintf("%v", asset.ID)

		usage, err := ParseUsage(asset.Usage)
		support.CheckErr(err)

		var dataAssetsProcessed = make([]string, 0)
		if asset.Data_assets_processed != nil {
			dataAssetsProcessed = make([]string, len(asset.Data_assets_processed))
			for i, parsedProcessedAsset := range asset.Data_assets_processed {
				referencedAsset := fmt.Sprintf("%v", parsedProcessedAsset)
				checkDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
				dataAssetsProcessed[i] = referencedAsset
			}
		}

		var dataAssetsStored = make([]string, 0)
		if asset.Data_assets_stored != nil {
			dataAssetsStored = make([]string, len(asset.Data_assets_stored))
			for i, parsedStoredAssets := range asset.Data_assets_stored {
				referencedAsset := fmt.Sprintf("%v", parsedStoredAssets)
				checkDataAssetTargetExists(referencedAsset, "technical asset '"+title+"'")
				dataAssetsStored[i] = referencedAsset
			}
		}

		technicalAssetType, err := ParseTechnicalAssetType(asset.Type)
		support.CheckErr(err)

		technicalAssetSize, err := ParseTechnicalAssetSize(asset.Size)
		support.CheckErr(err)

		technicalAssetTechnology, err := ParseTechnicalAssetTechnology(asset.Technology)
		support.CheckErr(err)

		encryption, err := ParseEncryptionStyle(asset.Encryption)
		support.CheckErr(err)

		technicalAssetMachine, err := ParseTechnicalAssetMachine(asset.Machine)
		support.CheckErr(err)
		confidentiality, err := confidentiality.ParseConfidentiality(asset.Confidentiality)
		support.CheckErr(err)
		integrity, err := criticality.ParseCriticality(asset.Integrity)
		support.CheckErr(err)

		availability, err := criticality.ParseCriticality(asset.Availability)
		support.CheckErr(err)

		dataFormatsAccepted := make([]DataFormat, 0)
		if asset.Data_formats_accepted != nil {
			for _, dataFormatName := range asset.Data_formats_accepted {
				parsedDataFormat, err := ParseDataFormatName(dataFormatName)
				support.CheckErr(err)
				dataFormatsAccepted = append(dataFormatsAccepted, parsedDataFormat)
			}
		}

		communicationLinks := make([]CommunicationLink, 0)
		if asset.Communication_links != nil {
			for commLinkTitle, commLink := range asset.Communication_links {
				constraint := true
				weight := 1
				authentication, err := ParseAuthentication(commLink.Authentication)
				support.CheckErr(err)
				authorization, err := ParseAuthorization(commLink.Authorization)
				support.CheckErr(err)
				usage, err := ParseUsage(commLink.Usage)
				support.CheckErr(err)
				protocol, err := ParseProtocol(commLink.Protocol)
				support.CheckErr(err)
				var dataAssetsSent []string
				var dataAssetsReceived []string

				if commLink.Data_assets_sent != nil {
					for _, dataAssetSent := range commLink.Data_assets_sent {
						referencedAsset := fmt.Sprintf("%v", dataAssetSent)
						checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
						dataAssetsSent = append(dataAssetsSent, referencedAsset)
					}
				}

				if commLink.Data_assets_received != nil {
					for _, dataAssetReceived := range commLink.Data_assets_received {
						referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
						checkDataAssetTargetExists(referencedAsset, "communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
						dataAssetsReceived = append(dataAssetsReceived, referencedAsset)
					}
				}

				if commLink.Diagram_tweak_weight > 0 {
					weight = commLink.Diagram_tweak_weight
				}

				constraint = !commLink.Diagram_tweak_constraint

				support.CheckErr(err)

				dataFlowTitle := fmt.Sprintf("%v", commLinkTitle)
				commLink := CommunicationLink{
					Id:                     createDataFlowId(id, dataFlowTitle),
					SourceId:               id,
					TargetId:               commLink.Target,
					Title:                  dataFlowTitle,
					Description:            withDefault(commLink.Description, dataFlowTitle),
					Protocol:               protocol,
					Authentication:         authentication,
					Authorization:          authorization,
					Usage:                  usage,
					Tags:                   checkTags(support.LowerCaseAndTrim(commLink.Tags), "communication link '"+commLinkTitle+"' of technical asset '"+title+"'"),
					VPN:                    commLink.VPN,
					IpFiltered:             commLink.IP_filtered,
					Readonly:               commLink.Readonly,
					DataAssetsSent:         dataAssetsSent,
					DataAssetsReceived:     dataAssetsReceived,
					DiagramTweakWeight:     weight,
					DiagramTweakConstraint: constraint,
				}
				communicationLinks = append(communicationLinks, commLink)
				// track all comm links
				CommunicationLinks[commLink.Id] = commLink
				// keep track of map of *all* comm links mapped by target-id (to be able to lookup "who is calling me" kind of things)
				IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId] = append(
					IncomingTechnicalCommunicationLinksMappedByTargetId[commLink.TargetId], commLink)
			}
		}

		support.CheckIdSyntax(id)
		if _, exists := ParsedModelRoot.TechnicalAssets[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		ParsedModelRoot.TechnicalAssets[id] = TechnicalAsset{
			Id:                      id,
			Usage:                   usage,
			Title:                   title, //fmt.Sprintf("%v", asset["title"]),
			Description:             withDefault(fmt.Sprintf("%v", asset.Description), title),
			Type:                    technicalAssetType,
			Size:                    technicalAssetSize,
			Technology:              technicalAssetTechnology,
			Tags:                    checkTags(support.LowerCaseAndTrim(asset.Tags), "technical asset '"+title+"'"),
			Machine:                 technicalAssetMachine,
			Internet:                asset.Internet,
			Encryption:              encryption,
			MultiTenant:             asset.Multi_tenant,
			Redundant:               asset.Redundant,
			CustomDevelopedParts:    asset.Custom_developed_parts,
			UsedAsClientByHuman:     asset.Used_as_client_by_human,
			OutOfScope:              asset.Out_of_scope,
			JustificationOutOfScope: fmt.Sprintf("%v", asset.Justification_out_of_scope),
			Owner:                   fmt.Sprintf("%v", asset.Owner),
			Confidentiality:         confidentiality,
			Integrity:               integrity,
			Availability:            availability,
			JustificationCiaRating:  fmt.Sprintf("%v", asset.Justification_cia_rating),
			DataAssetsProcessed:     dataAssetsProcessed,
			DataAssetsStored:        dataAssetsStored,
			DataFormatsAccepted:     dataFormatsAccepted,
			CommunicationLinks:      communicationLinks,
			DiagramTweakOrder:       asset.Diagram_tweak_order,
		}
	}

	// Trust Boundaries ===============================================================================
	checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries := make(map[string]bool)
	ParsedModelRoot.TrustBoundaries = make(map[string]TrustBoundary)
	for title, boundary := range modelInput.Trust_boundaries {
		id := fmt.Sprintf("%v", boundary.ID)

		var technicalAssetsInside = make([]string, 0)
		if boundary.Technical_assets_inside != nil {
			parsedInsideAssets := boundary.Technical_assets_inside
			technicalAssetsInside = make([]string, len(parsedInsideAssets))
			for i, parsedInsideAsset := range parsedInsideAssets {
				technicalAssetsInside[i] = fmt.Sprintf("%v", parsedInsideAsset)
				_, found := ParsedModelRoot.TechnicalAssets[technicalAssetsInside[i]]
				if !found {
					panic(errors.New("missing referenced technical asset " + technicalAssetsInside[i] + " at trust boundary '" + title + "'"))
				}
				if checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] {
					panic(errors.New("referenced technical asset " + technicalAssetsInside[i] + " at trust boundary '" + title + "' is modeled in multiple trust boundaries"))
				}
				checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries[technicalAssetsInside[i]] = true
				//fmt.Println("asset "+technicalAssetsInside[i]+" at i="+strconv.Itoa(i))
			}
		}

		var trustBoundariesNested = make([]string, 0)
		if boundary.Trust_boundaries_nested != nil {
			parsedNestedBoundaries := boundary.Trust_boundaries_nested
			trustBoundariesNested = make([]string, len(parsedNestedBoundaries))
			for i, parsedNestedBoundary := range parsedNestedBoundaries {
				trustBoundariesNested[i] = fmt.Sprintf("%v", parsedNestedBoundary)
			}
		}

		trustBoundaryType, err := ParseTrustBoundaryType(boundary.Type)
		support.CheckErr(err)
		trustBoundary := TrustBoundary{
			Id:                    id,
			Title:                 title, //fmt.Sprintf("%v", boundary["title"]),
			Description:           withDefault(fmt.Sprintf("%v", boundary.Description), title),
			Type:                  trustBoundaryType,
			Tags:                  checkTags(support.LowerCaseAndTrim(boundary.Tags), "trust boundary '"+title+"'"),
			TechnicalAssetsInside: technicalAssetsInside,
			TrustBoundariesNested: trustBoundariesNested,
		}
		support.CheckIdSyntax(id)
		if _, exists := ParsedModelRoot.TrustBoundaries[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		ParsedModelRoot.TrustBoundaries[id] = trustBoundary
		for _, technicalAsset := range trustBoundary.TechnicalAssetsInside {
			DirectContainingTrustBoundaryMappedByTechnicalAssetId[technicalAsset] = trustBoundary
			//fmt.Println("Asset "+technicalAsset+" is directly in trust boundary "+trustBoundary.Id)
		}
	}
	checkNestedTrustBoundariesExisting()

	// Shared Runtime ===============================================================================
	ParsedModelRoot.SharedRuntimes = make(map[string]SharedRuntime)
	for title, runtime := range modelInput.Shared_runtimes {
		id := fmt.Sprintf("%v", runtime.ID)

		var technicalAssetsRunning = make([]string, 0)
		if runtime.Technical_assets_running != nil {
			parsedRunningAssets := runtime.Technical_assets_running
			technicalAssetsRunning = make([]string, len(parsedRunningAssets))
			for i, parsedRunningAsset := range parsedRunningAssets {
				assetId := fmt.Sprintf("%v", parsedRunningAsset)
				CheckTechnicalAssetExists(assetId, "shared runtime '"+title+"'", false)
				technicalAssetsRunning[i] = assetId
			}
		}

		sharedRuntime := SharedRuntime{
			Id:                     id,
			Title:                  title, //fmt.Sprintf("%v", boundary["title"]),
			Description:            withDefault(fmt.Sprintf("%v", runtime.Description), title),
			Tags:                   checkTags((runtime.Tags), "shared runtime '"+title+"'"),
			TechnicalAssetsRunning: technicalAssetsRunning,
		}
		support.CheckIdSyntax(id)
		if _, exists := ParsedModelRoot.SharedRuntimes[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		ParsedModelRoot.SharedRuntimes[id] = sharedRuntime
		for _, technicalAssetId := range sharedRuntime.TechnicalAssetsRunning {
			DirectContainingSharedRuntimeMappedByTechnicalAssetId[technicalAssetId] = sharedRuntime
		}
	}

	// Individual Risk Categories (just used as regular risk categories) ===============================================================================
	ParsedModelRoot.IndividualRiskCategories = make(map[string]RiskCategory)
	for title, indivCat := range modelInput.Individual_risk_categories {
		id := fmt.Sprintf("%v", indivCat.ID)

		function, err := ParseRiskFunction(indivCat.Function)
		support.CheckErr(err)

		stride, err := ParseStride(indivCat.STRIDE)
		support.CheckErr(err)

		cat := RiskCategory{
			Id:                         id,
			Title:                      title,
			Description:                withDefault(fmt.Sprintf("%v", indivCat.Description), title),
			Impact:                     fmt.Sprintf("%v", indivCat.Impact),
			ASVS:                       fmt.Sprintf("%v", indivCat.ASVS),
			CheatSheet:                 fmt.Sprintf("%v", indivCat.Cheat_sheet),
			TestingGuide:               fmt.Sprintf("%v", indivCat.Testing_guide),
			Action:                     fmt.Sprintf("%v", indivCat.Action),
			Mitigation:                 fmt.Sprintf("%v", indivCat.Mitigation),
			Check:                      fmt.Sprintf("%v", indivCat.Check),
			DetectionLogic:             fmt.Sprintf("%v", indivCat.Detection_logic),
			RiskAssessment:             fmt.Sprintf("%v", indivCat.Risk_assessment),
			FalsePositives:             fmt.Sprintf("%v", indivCat.False_positives),
			Function:                   function,
			STRIDE:                     stride,
			ModelFailurePossibleReason: indivCat.Model_failure_possible_reason,
			CWE:                        indivCat.CWE,
		}
		support.CheckIdSyntax(id)
		if _, exists := ParsedModelRoot.IndividualRiskCategories[id]; exists {
			panic(errors.New("duplicate id used: " + id))
		}
		ParsedModelRoot.IndividualRiskCategories[id] = cat

		// NOW THE INDIVIDUAL RISK INSTANCES:
		//individualRiskInstances := make([]Risk, 0)
		if indivCat.Risks_identified != nil { // TODO: also add syntax checks of input YAML when linked asset is not found or when syntehtic-id is already used...
			for title, indivRiskInstance := range indivCat.Risks_identified {
				severity, err := ParseRiskSeverity(indivRiskInstance.Severity)
				support.CheckErr(err)
				exploitationLikelihood, err := ParseRiskExploitationLikelihood(indivRiskInstance.Exploitation_likelihood)
				support.CheckErr(err)
				exploitationImpact, err := ParseRiskExploitationImpact(indivRiskInstance.Exploitation_impact)
				support.CheckErr(err)
				dataBreachProbability, err := ParseDataBreachProbability(indivRiskInstance.Data_breach_probability)
				support.CheckErr(err)
				var mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string
				var dataBreachTechnicalAssetIDs []string

				if len(indivRiskInstance.Most_relevant_data_asset) > 0 {
					mostRelevantDataAssetId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_data_asset)
					checkDataAssetTargetExists(mostRelevantDataAssetId, "individual risk '"+title+"'")
				}

				if len(indivRiskInstance.Most_relevant_technical_asset) > 0 {
					mostRelevantTechnicalAssetId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_technical_asset)
					CheckTechnicalAssetExists(mostRelevantTechnicalAssetId, "individual risk '"+title+"'", false)
				}

				if len(indivRiskInstance.Most_relevant_communication_link) > 0 {
					mostRelevantCommunicationLinkId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_communication_link)
					checkCommunicationLinkExists(mostRelevantCommunicationLinkId, "individual risk '"+title+"'")
				}

				if len(indivRiskInstance.Most_relevant_trust_boundary) > 0 {
					mostRelevantTrustBoundaryId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_trust_boundary)
					checkTrustBoundaryExists(mostRelevantTrustBoundaryId, "individual risk '"+title+"'")
				}

				if len(indivRiskInstance.Most_relevant_shared_runtime) > 0 {
					mostRelevantSharedRuntimeId = fmt.Sprintf("%v", indivRiskInstance.Most_relevant_shared_runtime)
					checkSharedRuntimeExists(mostRelevantSharedRuntimeId, "individual risk '"+title+"'")
				}

				if indivRiskInstance.Data_breach_technical_assets != nil {
					dataBreachTechnicalAssetIDs = make([]string, len(indivRiskInstance.Data_breach_technical_assets))
					for i, parsedReferencedAsset := range indivRiskInstance.Data_breach_technical_assets {
						assetId := fmt.Sprintf("%v", parsedReferencedAsset)
						CheckTechnicalAssetExists(assetId, "data breach technical assets of individual risk '"+title+"'", false)
						dataBreachTechnicalAssetIDs[i] = assetId
					}
				}

				support.CheckErr(err)

				indivRiskInstance := Risk{
					SyntheticId:                     createSyntheticId(cat.Id, mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId),
					Title:                           fmt.Sprintf("%v", title),
					Category:                        cat,
					Severity:                        severity,
					ExploitationLikelihood:          exploitationLikelihood,
					ExploitationImpact:              exploitationImpact,
					MostRelevantDataAssetId:         mostRelevantDataAssetId,
					MostRelevantTechnicalAssetId:    mostRelevantTechnicalAssetId,
					MostRelevantCommunicationLinkId: mostRelevantCommunicationLinkId,
					MostRelevantTrustBoundaryId:     mostRelevantTrustBoundaryId,
					MostRelevantSharedRuntimeId:     mostRelevantSharedRuntimeId,
					DataBreachProbability:           dataBreachProbability,
					DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
				}
				GeneratedRisksByCategory[cat] = append(GeneratedRisksByCategory[cat], indivRiskInstance)
			}
		}
	}

	// Risk Tracking ===============================================================================
	ParsedModelRoot.RiskTracking = make(map[string]RiskTracking)
	for syntheticRiskId, riskTracking := range modelInput.Risk_tracking {
		justification := fmt.Sprintf("%v", riskTracking.Justification)
		checkedBy := fmt.Sprintf("%v", riskTracking.Checked_by)
		ticket := fmt.Sprintf("%v", riskTracking.Ticket)
		var date time.Time
		if len(riskTracking.Date) > 0 {
			date, err = time.Parse("2006-01-02", riskTracking.Date)
			if err != nil {
				panic(errors.New("unable to parse 'date' of risk tracking '" + syntheticRiskId + "': " + riskTracking.Date))
			}
		}

		status, err := ParseRiskStatus(riskTracking.Status)
		support.CheckErr(err)

		tracking := RiskTracking{
			SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
			Justification:   justification,
			CheckedBy:       checkedBy,
			Ticket:          ticket,
			Date:            date,
			Status:          status,
		}
		if strings.Contains(syntheticRiskId, "*") { // contains a wildcard char
			deferredRiskTrackingDueToWildcardMatching[syntheticRiskId] = tracking
		} else {
			ParsedModelRoot.RiskTracking[syntheticRiskId] = tracking
		}
	}

	// ====================== model consistency check (linking)
	for _, technicalAsset := range ParsedModelRoot.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			CheckTechnicalAssetExists(commLink.TargetId, "communication link '"+commLink.Title+"' of technical asset '"+technicalAsset.Title+"'", false)
		}
	}
	return ParsedModelRoot
}

func checkTags(tags []string, where string) []string {
	var tagsUsed = make([]string, 0)
	if tags != nil {
		tagsUsed = make([]string, len(tags))
		for i, parsedEntry := range tags {
			referencedTag := fmt.Sprintf("%v", parsedEntry)
			checkTagExists(referencedTag, where)
			tagsUsed[i] = referencedTag
		}
	}
	return tagsUsed
}

func checkTagExists(referencedTag, where string) {
	if !Contains(ParsedModelRoot.TagsAvailable, referencedTag) {
		panic(errors.New("missing referenced tag in overall tag list at " + where + ": " + referencedTag))
	}
}

func removePathElementsFromImageFiles(overview Overview) Overview {
	for i := range overview.Images {
		newValue := make(map[string]string)
		for file, desc := range overview.Images[i] {
			newValue[filepath.Base(file)] = desc
		}
		overview.Images[i] = newValue
	}
	return overview
}

func withDefault(value string, defaultWhenEmpty string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 0 && trimmed != "<nil>" {
		return trimmed
	}
	return strings.TrimSpace(defaultWhenEmpty)
}

func checkDataAssetTargetExists(referencedAsset, where string) {
	if _, ok := ParsedModelRoot.DataAssets[referencedAsset]; !ok {
		panic(errors.New("missing referenced data asset target at " + where + ": " + referencedAsset))
	}
}

func checkTrustBoundaryExists(referencedId, where string) {
	if _, ok := ParsedModelRoot.TrustBoundaries[referencedId]; !ok {
		panic(errors.New("missing referenced trust boundary at " + where + ": " + referencedId))
	}
}

func checkSharedRuntimeExists(referencedId, where string) {
	if _, ok := ParsedModelRoot.SharedRuntimes[referencedId]; !ok {
		panic(errors.New("missing referenced shared runtime at " + where + ": " + referencedId))
	}
}

func checkCommunicationLinkExists(referencedId, where string) {
	if _, ok := CommunicationLinks[referencedId]; !ok {
		panic(errors.New("missing referenced communication link at " + where + ": " + referencedId))
	}
}

func CheckTechnicalAssetExists(referencedAsset, where string, onlyForTweak bool) {
	if _, ok := ParsedModelRoot.TechnicalAssets[referencedAsset]; !ok {
		suffix := ""
		if onlyForTweak {
			suffix = " (only referenced in diagram tweak)"
		}
		panic(errors.New("missing referenced technical asset target" + suffix + " at " + where + ": " + referencedAsset))
	}
}

func checkNestedTrustBoundariesExisting() {
	for _, trustBoundary := range ParsedModelRoot.TrustBoundaries {
		for _, nestedId := range trustBoundary.TrustBoundariesNested {
			if _, ok := ParsedModelRoot.TrustBoundaries[nestedId]; !ok {
				panic(errors.New("missing referenced nested trust boundary: " + nestedId))
			}
		}
	}
}

func createDataFlowId(sourceAssetId, title string) string {
	reg, err := regexp.Compile("[^A-Za-z0-9]+")
	support.CheckErr(err)
	return sourceAssetId + ">" + strings.Trim(reg.ReplaceAllString(strings.ToLower(title), "-"), "- ")
}

func createSyntheticId(categoryId string,
	mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string) string {
	result := categoryId
	if len(mostRelevantTechnicalAssetId) > 0 {
		result += "@" + mostRelevantTechnicalAssetId
	}
	if len(mostRelevantCommunicationLinkId) > 0 {
		result += "@" + mostRelevantCommunicationLinkId
	}
	if len(mostRelevantTrustBoundaryId) > 0 {
		result += "@" + mostRelevantTrustBoundaryId
	}
	if len(mostRelevantSharedRuntimeId) > 0 {
		result += "@" + mostRelevantSharedRuntimeId
	}
	if len(mostRelevantDataAssetId) > 0 {
		result += "@" + mostRelevantDataAssetId
	}
	return result
}

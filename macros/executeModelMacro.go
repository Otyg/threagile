package macros

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	add_build_pipeline "github.com/otyg/threagile/macros/built-in/add-build-pipeline"
	add_vault "github.com/otyg/threagile/macros/built-in/add-vault"
	pretty_print "github.com/otyg/threagile/macros/built-in/pretty-print"
	remove_unused_tags "github.com/otyg/threagile/macros/built-in/remove-unused-tags"
	seed_risk_tracking "github.com/otyg/threagile/macros/built-in/seed-risk-tracking"
	seed_tags "github.com/otyg/threagile/macros/built-in/seed-tags"
	"github.com/otyg/threagile/model"
	"github.com/otyg/threagile/support"
	"gopkg.in/yaml.v2"
)

func ExecuteModelMacro(executeModelMacro *string, modelInput model.ModelInput, inputFilename string) {
	var macroDetails model.MacroDetails
	switch *executeModelMacro {
	case add_build_pipeline.GetMacroDetails().ID:
		macroDetails = add_build_pipeline.GetMacroDetails()
	case add_vault.GetMacroDetails().ID:
		macroDetails = add_vault.GetMacroDetails()
	case pretty_print.GetMacroDetails().ID:
		macroDetails = pretty_print.GetMacroDetails()
	case remove_unused_tags.GetMacroDetails().ID:
		macroDetails = remove_unused_tags.GetMacroDetails()
	case seed_risk_tracking.GetMacroDetails().ID:
		macroDetails = seed_risk_tracking.GetMacroDetails()
	case seed_tags.GetMacroDetails().ID:
		macroDetails = seed_tags.GetMacroDetails()
	default:
		log.Fatal("Unknown model macro: ", *executeModelMacro)
	}
	fmt.Println("Executing model macro:", macroDetails.ID)
	fmt.Println()
	fmt.Println()
	printBorder(len(macroDetails.Title), true)
	fmt.Println(macroDetails.Title)
	printBorder(len(macroDetails.Title), true)
	if len(macroDetails.Description) > 0 {
		fmt.Println(macroDetails.Description)
	}
	fmt.Println()
	reader := bufio.NewReader(os.Stdin)
	var err error
	var nextQuestion model.MacroQuestion
	for {
		switch macroDetails.ID {
		case add_build_pipeline.GetMacroDetails().ID:
			nextQuestion, err = add_build_pipeline.GetNextQuestion()
		case add_vault.GetMacroDetails().ID:
			nextQuestion, err = add_vault.GetNextQuestion()
		case pretty_print.GetMacroDetails().ID:
			nextQuestion, err = pretty_print.GetNextQuestion()
		case remove_unused_tags.GetMacroDetails().ID:
			nextQuestion, err = remove_unused_tags.GetNextQuestion()
		case seed_risk_tracking.GetMacroDetails().ID:
			nextQuestion, err = seed_risk_tracking.GetNextQuestion()
		case seed_tags.GetMacroDetails().ID:
			nextQuestion, err = seed_tags.GetNextQuestion()
		}
		support.CheckErr(err)
		if nextQuestion.NoMoreQuestions() {
			break
		}
		fmt.Println()
		printBorder(len(nextQuestion.Title), false)
		fmt.Println(nextQuestion.Title)
		printBorder(len(nextQuestion.Title), false)
		if len(nextQuestion.Description) > 0 {
			fmt.Println(nextQuestion.Description)
		}
		resultingMultiValueSelection := make([]string, 0)
		if nextQuestion.IsValueConstrained() {
			if nextQuestion.MultiSelect {
				selectedValues := make(map[string]bool, 0)
				for {
					fmt.Println("Please select (multiple executions possible) from the following values (use number to select/deselect):")
					fmt.Println("    0:", "SELECTION PROCESS FINISHED: CONTINUE TO NEXT QUESTION")
					for i, val := range nextQuestion.PossibleAnswers {
						number := i + 1
						padding, selected := "", " "
						if number < 10 {
							padding = " "
						}
						if val, exists := selectedValues[val]; exists && val {
							selected = "*"
						}
						fmt.Println(" "+selected+" "+padding+strconv.Itoa(number)+":", val)
					}
					fmt.Println()
					fmt.Print("Enter number to select/deselect (or 0 when finished): ")
					answer, err := reader.ReadString('\n')
					// convert CRLF to LF
					answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
					support.CheckErr(err)
					if val, err := strconv.Atoi(answer); err == nil { // flip selection
						if val == 0 {
							for key, selected := range selectedValues {
								if selected {
									resultingMultiValueSelection = append(resultingMultiValueSelection, key)
								}
							}
							break
						} else if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
							selectedValues[nextQuestion.PossibleAnswers[val-1]] = !selectedValues[nextQuestion.PossibleAnswers[val-1]]
						}
					}
				}
			} else {
				fmt.Println("Please choose from the following values (enter value directly or use number):")
				for i, val := range nextQuestion.PossibleAnswers {
					number := i + 1
					padding := ""
					if number < 10 {
						padding = " "
					}
					fmt.Println("   "+padding+strconv.Itoa(number)+":", val)
				}
			}
		}
		message := ""
		validResult := true
		if !nextQuestion.IsValueConstrained() || !nextQuestion.MultiSelect {
			fmt.Println()
			fmt.Println("Enter your answer (use 'BACK' to go one step back or 'QUIT' to quit without executing the model macro)")
			fmt.Print("Answer")
			if len(nextQuestion.DefaultAnswer) > 0 {
				fmt.Print(" (default '" + nextQuestion.DefaultAnswer + "')")
			}
			fmt.Print(": ")
			answer, err := reader.ReadString('\n')
			// convert CRLF to LF
			answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
			support.CheckErr(err)
			if len(answer) == 0 && len(nextQuestion.DefaultAnswer) > 0 { // accepting the default
				answer = nextQuestion.DefaultAnswer
			} else if nextQuestion.IsValueConstrained() { // convert number to value
				if val, err := strconv.Atoi(answer); err == nil {
					if val > 0 && val <= len(nextQuestion.PossibleAnswers) {
						answer = nextQuestion.PossibleAnswers[val-1]
					}
				}
			}
			if strings.ToLower(answer) == "quit" {
				fmt.Println("Quitting without executing the model macro")
				return
			} else if strings.ToLower(answer) == "back" {
				switch macroDetails.ID {
				case add_build_pipeline.GetMacroDetails().ID:
					message, validResult, err = add_build_pipeline.GoBack()
				case add_vault.GetMacroDetails().ID:
					message, validResult, err = add_vault.GoBack()
				case pretty_print.GetMacroDetails().ID:
					message, validResult, err = pretty_print.GoBack()
				case remove_unused_tags.GetMacroDetails().ID:
					message, validResult, err = remove_unused_tags.GoBack()
				case seed_risk_tracking.GetMacroDetails().ID:
					message, validResult, err = seed_risk_tracking.GoBack()
				case seed_tags.GetMacroDetails().ID:
					message, validResult, err = seed_tags.GoBack()
				}
			} else if len(answer) > 0 { // individual answer
				if nextQuestion.IsValueConstrained() {
					if !nextQuestion.IsMatchingValueConstraint(answer) {
						fmt.Println()
						fmt.Println(">>> INVALID <<<")
						fmt.Println("Answer does not match any allowed value. Please try again:")
						continue
					}
				}
				switch macroDetails.ID {
				case add_build_pipeline.GetMacroDetails().ID:
					message, validResult, err = add_build_pipeline.ApplyAnswer(nextQuestion.ID, answer)
				case add_vault.GetMacroDetails().ID:
					message, validResult, err = add_vault.ApplyAnswer(nextQuestion.ID, answer)
				case pretty_print.GetMacroDetails().ID:
					message, validResult, err = pretty_print.ApplyAnswer(nextQuestion.ID, answer)
				case remove_unused_tags.GetMacroDetails().ID:
					message, validResult, err = remove_unused_tags.ApplyAnswer(nextQuestion.ID, answer)
				case seed_risk_tracking.GetMacroDetails().ID:
					message, validResult, err = seed_risk_tracking.ApplyAnswer(nextQuestion.ID, answer)
				case seed_tags.GetMacroDetails().ID:
					message, validResult, err = seed_tags.ApplyAnswer(nextQuestion.ID, answer)
				}
			}
		} else {
			switch macroDetails.ID {
			case add_build_pipeline.GetMacroDetails().ID:
				message, validResult, err = add_build_pipeline.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
			case add_vault.GetMacroDetails().ID:
				message, validResult, err = add_vault.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
			case pretty_print.GetMacroDetails().ID:
				message, validResult, err = pretty_print.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
			case remove_unused_tags.GetMacroDetails().ID:
				message, validResult, err = remove_unused_tags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
			case seed_risk_tracking.GetMacroDetails().ID:
				message, validResult, err = seed_risk_tracking.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
			case seed_tags.GetMacroDetails().ID:
				message, validResult, err = seed_tags.ApplyAnswer(nextQuestion.ID, resultingMultiValueSelection...)
			}
		}
		support.CheckErr(err)
		if !validResult {
			fmt.Println()
			fmt.Println(">>> INVALID <<<")
		}
		fmt.Println(message)
		fmt.Println()
	}
	for {
		fmt.Println()
		fmt.Println()
		fmt.Println("#################################################################")
		fmt.Println("Do you want to execute the model macro (updating the model file)?")
		fmt.Println("#################################################################")
		fmt.Println()
		fmt.Println("The following changes will be applied:")
		var changes []string
		message := ""
		validResult := true
		var err error
		switch macroDetails.ID {
		case add_build_pipeline.GetMacroDetails().ID:
			changes, message, validResult, err = add_build_pipeline.GetFinalChangeImpact(&modelInput)
		case add_vault.GetMacroDetails().ID:
			changes, message, validResult, err = add_vault.GetFinalChangeImpact(&modelInput)
		case pretty_print.GetMacroDetails().ID:
			changes, message, validResult, err = pretty_print.GetFinalChangeImpact(&modelInput)
		case remove_unused_tags.GetMacroDetails().ID:
			changes, message, validResult, err = remove_unused_tags.GetFinalChangeImpact(&modelInput)
		case seed_risk_tracking.GetMacroDetails().ID:
			changes, message, validResult, err = seed_risk_tracking.GetFinalChangeImpact(&modelInput)
		case seed_tags.GetMacroDetails().ID:
			changes, message, validResult, err = seed_tags.GetFinalChangeImpact(&modelInput)
		}
		support.CheckErr(err)
		for _, change := range changes {
			fmt.Println(" -", change)
		}
		if !validResult {
			fmt.Println()
			fmt.Println(">>> INVALID <<<")
		}
		fmt.Println()
		fmt.Println(message)
		fmt.Println()
		fmt.Print("Apply these changes to the model file?\nType Yes or No: ")
		answer, err := reader.ReadString('\n')
		// convert CRLF to LF
		answer = strings.TrimSpace(strings.Replace(answer, "\n", "", -1))
		support.CheckErr(err)
		answer = strings.ToLower(answer)
		fmt.Println()
		if answer == "yes" || answer == "y" {
			message := ""
			validResult := true
			var err error
			switch macroDetails.ID {
			case add_build_pipeline.GetMacroDetails().ID:
				message, validResult, err = add_build_pipeline.Execute(&modelInput)
			case add_vault.GetMacroDetails().ID:
				message, validResult, err = add_vault.Execute(&modelInput)
			case pretty_print.GetMacroDetails().ID:
				message, validResult, err = pretty_print.Execute(&modelInput)
			case remove_unused_tags.GetMacroDetails().ID:
				message, validResult, err = remove_unused_tags.Execute(&modelInput)
			case seed_risk_tracking.GetMacroDetails().ID:
				message, validResult, err = seed_risk_tracking.Execute(&modelInput)
			case seed_tags.GetMacroDetails().ID:
				message, validResult, err = seed_tags.Execute(&modelInput)
			}
			support.CheckErr(err)
			if !validResult {
				fmt.Println()
				fmt.Println(">>> INVALID <<<")
			}
			fmt.Println(message)
			fmt.Println()
			backupFilename := inputFilename + ".backup"
			fmt.Println("Creating backup model file:", backupFilename) // TODO add random files in /dev/shm space?
			_, err = support.CopyFile(inputFilename, backupFilename)
			support.CheckErr(err)
			fmt.Println("Updating model")
			yamlBytes, err := yaml.Marshal(modelInput)
			support.CheckErr(err)
			/*
				yamlBytes = model.ReformatYAML(yamlBytes)
			*/
			fmt.Println("Writing model file:", inputFilename)
			err = ioutil.WriteFile(inputFilename, yamlBytes, 0400)
			support.CheckErr(err)
			fmt.Println("Model file successfully updated")
			return
		} else if answer == "no" || answer == "n" {
			fmt.Println("Quitting without executing the model macro")
			return
		}
	}
	return
}
func printBorder(length int, bold bool) {
	char := "-"
	if bold {
		char = "="
	}
	for i := 1; i <= length; i++ {
		fmt.Print(char)
	}
	fmt.Println()
}

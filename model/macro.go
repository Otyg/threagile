package model

import "strings"

type MacroDetails struct {
	ID, Title, Description string
}

type MacroQuestion struct {
	ID, Title, Description string
	PossibleAnswers        []string
	MultiSelect            bool
	DefaultAnswer          string
}

const NoMoreQuestionsID = ""

func NoMoreQuestions() MacroQuestion {
	return MacroQuestion{
		ID:              NoMoreQuestionsID,
		Title:           "",
		Description:     "",
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "",
	}
}

func (what MacroQuestion) NoMoreQuestions() bool {
	return what.ID == NoMoreQuestionsID
}

func (what MacroQuestion) IsValueConstrained() bool {
	return what.PossibleAnswers != nil && len(what.PossibleAnswers) > 0
}

func (what MacroQuestion) IsMatchingValueConstraint(answer string) bool {
	if what.IsValueConstrained() {
		for _, val := range what.PossibleAnswers {
			if strings.EqualFold(val, answer) {
				return true
			}
		}
		return false
	}
	return true
}

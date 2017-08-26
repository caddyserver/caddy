package kingpin

// HintAction is a function type who is expected to return a slice of possible
// command line arguments.
type HintAction func() []string
type completionsMixin struct {
	hintActions        []HintAction
	builtinHintActions []HintAction
}

func (a *completionsMixin) addHintAction(action HintAction) {
	a.hintActions = append(a.hintActions, action)
}

// Allow adding of HintActions which are added internally, ie, EnumVar
func (a *completionsMixin) addHintActionBuiltin(action HintAction) {
	a.builtinHintActions = append(a.builtinHintActions, action)
}

func (a *completionsMixin) resolveCompletions() []string {
	var hints []string

	options := a.builtinHintActions
	if len(a.hintActions) > 0 {
		// User specified their own hintActions. Use those instead.
		options = a.hintActions
	}

	for _, hintAction := range options {
		hints = append(hints, hintAction()...)
	}
	return hints
}

package runfs

// ExpectedStages is the default execution plan for a full audit run.
// Persisting this before any work begins lets validation detect a stage that
// never started. Global taint prescan is opt-in; use ExpectedStagesWithOptions
// when optional pre-investigation stages are enabled.
func ExpectedStages(legacyPrior bool) []string {
	return ExpectedStagesWithOptions(legacyPrior, false)
}

// ExpectedStagesWithOptions builds the deterministic stage sequence matching
// the run's configured optional stages.
func ExpectedStagesWithOptions(legacyPrior, taintPrescan bool) []string {
	stages := []string{"preprocess", "repo_index", "project_map"}
	if taintPrescan {
		stages = append(stages, "taint_prescan")
	}
	if legacyPrior {
		stages = append(stages, "architecture", "invariants")
	}
	return append(stages, "l3_planner", "cases_enrich", "expert", "challenger", "verifier", "arbiter")
}

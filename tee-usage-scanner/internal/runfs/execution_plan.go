package runfs

// ExpectedStages is the execution plan for a full audit run. Persisting this
// before any work begins lets validation detect a stage that never started.
func ExpectedStages(legacyPrior bool) []string {
	stages := []string{"preprocess", "repo_index", "project_map", "taint_prescan"}
	if legacyPrior {
		stages = append(stages, "architecture", "invariants")
	}
	return append(stages, "l3_planner", "cases_enrich", "expert", "challenger", "verifier", "arbiter")
}

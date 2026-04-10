package scanner

type edgeKey struct {
	Source string
	Target string
	Kind   string
}

func MergeGraphResults(results ...GraphResult) GraphResult {
	seenNodes := make(map[string]bool)
	seenEdges := make(map[edgeKey]bool)
	var merged GraphResult

	for _, r := range results {
		for _, n := range r.Nodes {
			if !seenNodes[n.ID] {
				seenNodes[n.ID] = true
				merged.Nodes = append(merged.Nodes, n)
			}
		}
		for _, e := range r.Edges {
			key := edgeKey{Source: e.Source, Target: e.Target, Kind: e.Kind}
			if !seenEdges[key] {
				seenEdges[key] = true
				merged.Edges = append(merged.Edges, e)
			}
		}
	}
	return merged
}

package planner

// LoopDetector tracks consecutive identical action requests. The
// planner main loop calls ShouldReject before dispatching an action,
// then Record after a successful dispatch. The default policy
// rejects an action when it would be the third consecutive
// identical (action_name, args) tuple.
//
// Identity is based on the action name + the raw args string. Two
// requests with semantically equivalent but textually different args
// are NOT considered identical (this is intentional — the LLM
// should be free to refine).
type LoopDetector struct {
	lastAction string
	lastArgs   string
	count      int
}

func NewLoopDetector() *LoopDetector {
	return &LoopDetector{}
}

// ShouldReject reports whether dispatching this action would be the
// third consecutive identical call.
func (d *LoopDetector) ShouldReject(name, args string) bool {
	if name == d.lastAction && args == d.lastArgs {
		return d.count >= 2
	}
	return false
}

// Record updates the detector after an action dispatch.
func (d *LoopDetector) Record(name, args string) {
	if name == d.lastAction && args == d.lastArgs {
		d.count++
		return
	}
	d.lastAction = name
	d.lastArgs = args
	d.count = 1
}

// StallDetector tracks consecutive rounds with no change to the
// candidate count. After 2 consecutive no-change rounds it signals
// stall (i.e., the LLM is spinning without producing new candidates).
type StallDetector struct {
	lastCount        int
	consecutiveStill int
	hasFirstObs      bool
}

func NewStallDetector() *StallDetector {
	return &StallDetector{}
}

// RecordRound feeds the current candidate count to the detector.
func (s *StallDetector) RecordRound(candidateCount int) {
	if !s.hasFirstObs {
		s.lastCount = candidateCount
		s.consecutiveStill = 0
		s.hasFirstObs = true
		return
	}
	if candidateCount == s.lastCount {
		s.consecutiveStill++
	} else {
		s.consecutiveStill = 0
		s.lastCount = candidateCount
	}
}

// Stalled returns true when the candidate count has been unchanged
// for at least 2 consecutive rounds since the first observation.
func (s *StallDetector) Stalled() bool {
	return s.consecutiveStill >= 2
}

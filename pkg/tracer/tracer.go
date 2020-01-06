package tracer

import "github.com/mrtc0/cxray/pkg/logger"

// Tracer interface
// Load() is load a BPF tracer program
// Watch() is watch event (e.g. perfmap), log to a terminal
// Start() is start BPF tracer program
// Stop() is stop BPF tracer program
type Tracer interface {
	Load() error
	Watch() (*logger.EventLog, error)
	Start()
	Stop()
	Close()
}

// Tracers is registerd some tracers
var Tracers map[string]Tracer

// Init is registerd tracers to Tracers variable
func Init() {
	Tracers = map[string]Tracer{}
}

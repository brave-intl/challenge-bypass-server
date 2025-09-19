package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// When the service panics and restarts we get a prometheus error indicating that our
// collectors are already registered. To handle this case, we check if a registration
// failure is the result of an already registered collector and use that one if so.
// This is all side effects due to the way that prometheus handles collectors as
// interfaces with pointers etc.
func MustRegisterIfNotRegistered(
	registry prometheus.Registerer,
	collectors ...prometheus.Collector,
) {
	for _, collector := range collectors {
		err := registry.Register(collector)
		if err != nil {
			var alreadyRegisteredError prometheus.AlreadyRegisteredError
			if !errors.As(err, &alreadyRegisteredError) {
				panic(err)
			}
		}
	}
}

package metrics

import (
	"errors"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrorsByType counts errors broken down by a bounded "reason" label so
// operators can graph error volume by failure mode. For HTTP errors the
// "endpoint" (chi route pattern) and "code" (HTTP status) labels are also set;
// they are empty for non-HTTP (Kafka/processing) errors.
//
// The reason label MUST be a bounded, static string. Never pass a raw error
// message or anything containing request-scoped data (request IDs, tokens),
// or Prometheus cardinality will explode.
var ErrorsByType = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cbp_errors_by_type_total",
		Help: "Errors by bounded reason label (plus endpoint/code for HTTP errors).",
	},
	[]string{"reason", "endpoint", "code"},
)

// CountError records a non-HTTP (Kafka/processing) error under a bounded reason.
func CountError(reason string) {
	ErrorsByType.WithLabelValues(reason, "", "").Inc()
}

// CountHTTPError records an HTTP handler error under the given route pattern and
// status code. The reason is fixed to "http" so HTTP errors group together.
func CountHTTPError(endpoint string, code int) {
	ErrorsByType.WithLabelValues("http", endpoint, strconv.Itoa(code)).Inc()
}

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

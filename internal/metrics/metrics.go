package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector bundles all VPN observability metrics specified in Section 7.
type Collector struct {
	Registry            *prometheus.Registry
	ActiveSessions      prometheus.Gauge
	RxBytesTotal        prometheus.Counter
	TxBytesTotal        prometheus.Counter
	RxPacketsTotal      prometheus.Counter
	TxPacketsTotal      prometheus.Counter
	HandshakesTotal     *prometheus.CounterVec
	PacketsDroppedTotal *prometheus.CounterVec
	KeyRotationsTotal   prometheus.Counter
}

// NewCollector creates an isolated Prometheus registry and registers VPN server metrics.
func NewCollector(includeRuntime bool) *Collector {
	reg := prometheus.NewRegistry()
	if includeRuntime {
		reg.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
	}

	c := &Collector{
		Registry: reg,
		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vpn_active_sessions",
			Help: "Current number of active VPN client sessions.",
		}),
		RxBytesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vpn_rx_bytes_total",
			Help: "Total decrypted IPv4 payload bytes received from VPN clients.",
		}),
		TxBytesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vpn_tx_bytes_total",
			Help: "Total plaintext IPv4 payload bytes encrypted and transmitted to VPN clients.",
		}),
		RxPacketsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vpn_rx_packets_total",
			Help: "Total valid data packets received from VPN clients.",
		}),
		TxPacketsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vpn_tx_packets_total",
			Help: "Total data packets encrypted and sent to VPN clients.",
		}),
		HandshakesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vpn_handshakes_total",
			Help: "Total handshake attempts partitioned by result.",
		}, []string{"result"}),
		PacketsDroppedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vpn_packets_dropped_total",
			Help: "Total dropped packets partitioned by drop reason.",
		}, []string{"reason"}),
		KeyRotationsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vpn_key_rotations_total",
			Help: "Total completed session key rotations.",
		}),
	}

	reg.MustRegister(
		c.ActiveSessions,
		c.RxBytesTotal,
		c.TxBytesTotal,
		c.RxPacketsTotal,
		c.TxPacketsTotal,
		c.HandshakesTotal,
		c.PacketsDroppedTotal,
		c.KeyRotationsTotal,
	)
	return c
}

// Handler returns an http.Handler serving Prometheus exposition format.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.Registry, promhttp.HandlerOpts{})
}

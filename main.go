package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

const Namespace = "network_exporter"

type Network struct {
	DNS struct {
		Every   time.Duration `yaml:"every"`
		Timeout time.Duration `yaml:"timeout"`
		Names   []string      `yaml:"names"`
	} `yaml:"dns"`
	Icmp struct {
		Every   time.Duration `yaml:"every"`
		Refresh time.Duration `yaml:"refresh"`
		Timeout time.Duration `yaml:"timeout"`
		Ips     []string      `yaml:"ips"`
	} `yaml:"icmp"`
}

var (
	config = flag.String("config", "network.yaml", "Path to config yaml file")
	debug  = flag.Bool("debug", false, "Use debug log level")
	listen = flag.String("listen", ":8080", "addr:port to listen on")

	// DNS
	dnsHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:                      Namespace,
		Name:                           "dns_duration_seconds",
		Buckets:                        prometheus.ExponentialBuckets(0.0007, 1.3, 30),
		NativeHistogramBucketFactor:    1.005,
		NativeHistogramMaxBucketNumber: 100,
		Help:                           "DNS latency",
	}, []string{"addr"})

	dnsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "dns_up",
		Help:      "DNS up",
	}, []string{"addr"})

	// ICMP
	icmpHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:                      Namespace,
		Name:                           "icmp_duration_seconds",
		Buckets:                        prometheus.ExponentialBuckets(0.0007, 1.3, 30),
		NativeHistogramBucketFactor:    1.005,
		NativeHistogramMaxBucketNumber: 100,
		Help:                           "ICMP latency",
	}, []string{"addr", "ip"})

	icmpGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "icmp_up",
		Help:      "ICMP up",
	}, []string{"addr", "ip"})
)

func main() {
	flag.Parse()
	if *debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	network, err := getConfig()
	if err != nil {
		panic(err)
	}
	for _, ip := range network.Icmp.Ips {
		go ping(ip, network.Icmp.Every, network.Icmp.Refresh)
	}
	for _, name := range network.DNS.Names {
		go dns(name, network.DNS.Every)
	}
	http.Handle("/metrics", promhttp.Handler())
	slog.Info("Starting",
		slog.String("config", *config),
		slog.String("listen", *listen),
	)
	if err := http.ListenAndServe(*listen, nil); err != nil {
		slog.Error("Server failed", slog.Any("err", err))
	}
}

func newPingerMust(addr string) *probing.Pinger {
	for {
		pinger, err := probing.NewPinger(addr)
		if err != nil {
			slog.Error("Pinger creation failed",
				slog.String("addr", addr),
				slog.Any("err", err),
			)
			time.Sleep(time.Second * 90)
		}
		return pinger
	}
}

func getConfig() (*Network, error) {
	data, err := os.ReadFile(*config)
	if err != nil {
		return nil, err
	}
	network := new(Network)
	return network, yaml.Unmarshal(data, network)
}

func dns(addr string, interval time.Duration) {
	// Because this is a dns check, we don't care if there is an error getting
	// a new Pinger. The entire point is to test action, which happens via the
	// pinger.Resolve() check below.
	pinger, _ := probing.NewPinger(addr)
	go func() {
		for range time.NewTicker(interval).C {
			var up float64
			start := time.Now()
			err := pinger.Resolve()
			dur := time.Now().Sub(start)
			dnsHist.WithLabelValues(addr).Observe(dur.Seconds())
			if err == nil {
				up = 1
			}
			dnsGauge.WithLabelValues(addr).Set(up)
			slog.Debug("DNS", slog.String("addr", addr),
				slog.Int("up", int(up)),
				slog.Duration("ms", dur),
				slog.Any("err", err),
			)
		}
	}()
}

func setupPinger(addr string, interval time.Duration) *probing.Pinger {
	pinger := newPingerMust(addr)
	pinger.Interval = interval
	pinger.OnRecv = func(pkt *probing.Packet) {
		var up float64
		if pkt.Nbytes > 0 {
			up = 1
		}
		icmpHist.WithLabelValues(pkt.Addr, pkt.IPAddr.String()).Observe(pkt.Rtt.Seconds())
		icmpGauge.WithLabelValues(pkt.Addr, pkt.IPAddr.String()).Set(up)
		slog.Debug("ICMP",
			slog.String("ip", pkt.IPAddr.String()),
			slog.Int("up", int(up)),
			slog.Duration("ms", pkt.Rtt),
		)
	}
	pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
		slog.Debug("ICMP (DUP!)",
			slog.String("ip", pkt.IPAddr.String()),
			slog.Duration("ms", pkt.Rtt),
		)
	}
	go pinger.Run()
	return pinger
}

func ping(addr string, interval, refresh time.Duration) {
	if refresh == 0 {
		slog.Info("Refresh not configured, exiting",
			slog.String("addr", addr),
			slog.Duration("refresh", refresh),
		)
		return
	}
	pinger := setupPinger(addr, interval)
	go func() {
		for range time.NewTicker(refresh).C {
			slog.Info("Making fresh pinger",
				slog.String("addr", addr),
				slog.Duration("interval", interval),
				slog.Duration("refesh", refresh),
			)
			pinger.Stop()
			pinger = setupPinger(addr, interval)
		}
	}()
}

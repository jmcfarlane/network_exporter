package main

import (
	"flag"
	"io/ioutil"
	"net/http"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
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
	listen = flag.String("listen", ":8080", "addr:port to listen on")

	// DNS
	dnsHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "dns_duration_seconds",
		Buckets:   prometheus.ExponentialBuckets(0.0007, 1.3, 30),
		Help:      "DNS latency",
	}, []string{"addr"})

	dnsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "dns_up",
		Help:      "DNS up",
	}, []string{"addr"})

	// ICMP
	icmpHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "icmp_duration_seconds",
		Buckets:   prometheus.ExponentialBuckets(0.0007, 1.3, 30),
		Help:      "ICMP latency",
	}, []string{"addr", "ip"})

	icmpGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "icmp_up",
		Help:      "ICMP up",
	}, []string{"addr", "ip"})
)

func main() {
	flag.Parse()
	network, err := getConfig()
	if err != nil {
		panic(err)
	}
	for _, ip := range network.Icmp.Ips {
		ping(ip, network.Icmp.Every, network.Icmp.Refresh)
	}
	for _, name := range network.DNS.Names {
		dns(name, network.DNS.Every)
	}
	http.Handle("/metrics", promhttp.Handler())
	log.Info().Str("listen", *listen).Str("config", *config).Msg("Starting")
	log.Info().Err(http.ListenAndServe(*listen, nil)).Msg("Done")
}

func getConfig() (*Network, error) {
	data, err := ioutil.ReadFile(*config)
	if err != nil {
		return nil, err
	}
	network := new(Network)
	return network, yaml.Unmarshal(data, network)
}

func dns(addr string, interval time.Duration) {
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
			log.Info().Str("addr", addr).Dur("ms", dur).Err(err).Int("up", int(up)).Msg("DNS")
		}
	}()
}

func setupPinger(addr string, interval, refresh time.Duration) *probing.Pinger {
	pinger, err := probing.NewPinger(addr)
	log.Info().Str("addr", addr).Err(err).Msg("NewPinger")
	pinger.Interval = interval
	pinger.OnRecv = func(pkt *probing.Packet) {
		var up float64
		if pkt.Nbytes > 0 {
			up = 1
		}
		icmpHist.WithLabelValues(pkt.Addr, pkt.IPAddr.String()).Observe(pkt.Rtt.Seconds())
		icmpGauge.WithLabelValues(pkt.Addr, pkt.IPAddr.String()).Set(up)
		log.Info().Str("ip", pkt.IPAddr.String()).Dur("ms", pkt.Rtt).Int("up", int(up)).Msg("ICMP")
	}
	pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
		log.Info().Str("ip", pkt.IPAddr.String()).Dur("ms", pkt.Rtt).Msg("ICMP (DUP!)")
	}
	go pinger.Run()
	return pinger
}

func ping(addr string, interval, refresh time.Duration) {
	pinger := setupPinger(addr, interval, refresh)
	if refresh == 0 {
		return
	}
	go func() {
		for range time.NewTicker(refresh).C {
			pinger.Stop()
			pinger = setupPinger(addr, interval, refresh)
		}
	}()
}

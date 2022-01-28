package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"context"
	"errors"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"gopkg.in/yaml.v2"

	"software.sslmate.com/src/go-pkcs12"

	kuberrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	ccExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "expiry_time_cc_cert_days",
		Help: "CC certificate expiration time in days",
	})
	ingressExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "expiry_time_ingress_cert_days",
		Help: "Ingress certificate expiration time in days",
	})
	kafkaExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "expiry_time_kafka_cert_days",
		Help: "Kafka certificate expiration time in days",
	})
	ttExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "expiry_time_tarantool_cert_days",
		Help: "Tarantool certificate expiration time in days",
	})
)

type Config struct {
	RemoteTarantool struct {
		Port string `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"remoteTarantool"`
	Secrets struct {
		Kafka struct {
			SecretName string `yaml:"secretName"`
			Key        string `yaml:"key"`
		} `yaml:"kafka"`
		CC struct {
			SecretName string `yaml:"secretName"`
			Key        string `yaml:"key"`
		} `yaml:"cc"`
		Ingress struct {
			SecretName string `yaml:"secretName"`
			Key        string `yaml:"key"`
		} `yaml:"ingress"`
	} `yaml:"secrets"`

	MetricPath string `yaml:"metricPath"` // path for prometheus metrics
	Namespace  string `yanl:"namespace"`  // oShift namespace to retrive secrets
}

// State represents the last-known state of a URL.
type State struct {
	url    string
	status string
}

//TODO add conf pass flag
func ReadConfig(configPath string) *Config {
	// Create config structure
	config := &Config{}
	// Open config file
	filename, _ := filepath.Abs(configPath)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatal(err)
	}
	return config
}

func checkRemoteCertExpiry(host, port string) (float64, error) {
	endpoint := host + ":" + port
	conn, err := tls.Dial("tcp", endpoint, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("Can`t connect to host - " + err.Error())
		return 0, errors.New("Can`t check remote host cert expiry")
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	t := time.Now()
	diff := math.Round(expiry.Sub(t).Hours() / 24)

	return diff, nil
}

func checkOshiftCertExpiry(ns string, cname string, ckey string, clientset *kubernetes.Clientset) float64 {
	s, err := clientset.CoreV1().Secrets(ns).Get(context.TODO(), cname, metav1.GetOptions{})
	if statusError, isStatus := err.(*kuberrors.StatusError); isStatus {
		log.Printf("Failed to get secret %v\n", statusError.ErrStatus.Message)
	} else if err != nil {
		log.Printf("Failed to get secret: %v", err)
	}

	block, _ := pem.Decode([]byte(s.Data[ckey]))
	if block == nil {
		log.Print("Failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Print("Failed to parse certificate: " + err.Error())
	}

	t := time.Now()
	diff := math.Round(cert.NotAfter.Sub(t).Hours() / 24)

	return diff
}

func checkOshiftPfxExpiry(ns string, cname string, ckey string, pass string, clientset *kubernetes.Clientset) float64 {
	s, err := clientset.CoreV1().Secrets(ns).Get(context.TODO(), cname, metav1.GetOptions{})
	if statusError, isStatus := err.(*kuberrors.StatusError); isStatus {
		log.Printf("Failed to get secret %v\n", statusError.ErrStatus.Message)
	} else if err != nil {
		log.Printf("Failed to get secret: %v", err)
	}

	_, cert, err := pkcs12.Decode(s.Data[ckey], pass)
	if err != nil {
		log.Print("Failed to decode PKCS12 certificate")
	}

	t := time.Now()
	diff := math.Round(cert.NotAfter.Sub(t).Hours() / 24)

	return diff
}

// Simple cycles for certificate metrics updates
func (conf Config) collectCertMetrics(clientset *kubernetes.Clientset) {
	if conf.Secrets.CC.SecretName != "" && conf.Secrets.CC.Key != "" {
		go func() {
			for {
				ccExpiry.Set(checkOshiftCertExpiry(conf.Namespace, conf.Secrets.CC.SecretName, conf.Secrets.CC.Key, clientset))
				time.Sleep(1 * time.Hour)
			}
		}()
	} else {
		log.Print("CC secret`s properties is not set and cert expiry checks will be skipped")
	}
	if conf.Secrets.Ingress.SecretName != "" && conf.Secrets.Ingress.Key != "" {
		go func() {
			for {
				ingressExpiry.Set(checkOshiftCertExpiry(conf.Namespace, conf.Secrets.Ingress.SecretName, conf.Secrets.Ingress.Key, clientset))
				time.Sleep(1 * time.Hour)
			}
		}()
	} else {
		log.Print("Ingress secret`s properties is not set and cert expiry checks will be skipped")
	}
	if conf.Secrets.Kafka.SecretName != "" && conf.Secrets.Kafka.Key != "" {
		go func() {
			kafkaPass := os.Getenv("KAFKA_PASS")
			if kafkaPass == "" {
				log.Fatal("Kafka pfx password is not set.")
			}
			for {
				kafkaExpiry.Set(checkOshiftPfxExpiry(conf.Namespace, conf.Secrets.Kafka.SecretName, conf.Secrets.Kafka.Key, kafkaPass, clientset))
				time.Sleep(1 * time.Hour)
			}
		}()
	} else {
		log.Print("Kafka secret`s properties is not set and cert expiry checks will be skipped")
	}
	if conf.RemoteTarantool.Host != "" {
		go func() {
			for {
				val, err := checkRemoteCertExpiry(conf.RemoteTarantool.Host, conf.RemoteTarantool.Port)
				if err != nil {
					log.Printf("Tarantool cert expiry metric will not be updated: " + err.Error())
				} else {
					ttExpiry.Set(val)
				}
				time.Sleep(1 * time.Hour)
			}
		}()
	}
}

func main() {

	log.Print("Reading config...")
	//!!!!!!!!!!change to /app/config.yaml or ./config.yaml for local
	conf := ReadConfig("/app/config.yaml")

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("Port is not set.")
	}

	log.Print("Starting the service...")

	//Allow unknown authority
	//http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	},
	)

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	conf.collectCertMetrics(clientset)
	http.Handle(conf.MetricPath, promhttp.Handler())

	srv := http.Server{
		Addr: ":" + port,
		//Addr: ":8000",
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// Error starting or closing listener:
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()
	log.Print("The service is ready to listen and serve.")

	<-idleConnsClosed

}

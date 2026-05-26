package geo

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type GeoIPDB struct {
	cityDB *maxminddb.Reader
	asnDB  *maxminddb.Reader
	mu     sync.RWMutex
}

// NewGeoIPDB loads GeoLite2 City and ASN .mmdb files from dir.
// Returns nil if files not found (caller should fall back to API).
func NewGeoIPDB(dir string) *GeoIPDB {
	cityPath := filepath.Join(dir, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(dir, "GeoLite2-ASN.mmdb")

	cityDB, err := maxminddb.Open(cityPath)
	if err != nil {
		log.Printf("[geoip] city db not found: %s (%v)", cityPath, err)
		return nil
	}

	asnDB, err := maxminddb.Open(asnPath)
	if err != nil {
		log.Printf("[geoip] asn db not found: %s (%v)", asnPath, err)
		cityDB.Close()
		return nil
	}

	log.Printf("[geoip] loaded GeoLite2 City+ASN from %s", dir)
	return &GeoIPDB{cityDB: cityDB, asnDB: asnDB}
}

func (db *GeoIPDB) Close() {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.cityDB != nil {
		db.cityDB.Close()
		db.cityDB = nil
	}
	if db.asnDB != nil {
		db.asnDB.Close()
		db.asnDB = nil
	}
}

// Lookup returns GeoInfo for an IP using local .mmdb databases.
// Returns nil if IP not found or DB not available.
func (db *GeoIPDB) Lookup(ipStr string) *GeoInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.cityDB == nil {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	var city struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
	}
	if err := db.cityDB.Lookup(ip, &city); err != nil {
		return nil
	}
	if city.Country.ISOCode == "" {
		return nil
	}

	isp := ""
	if db.asnDB != nil {
		var asn struct {
			AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		}
		if err := db.asnDB.Lookup(ip, &asn); err == nil {
			isp = asn.AutonomousSystemOrganization
		}
	}

	cityName := city.City.Names["en"]
	if cityName == "" {
		cityName = city.Country.ISOCode
	}
	if isp == "" {
		isp = "Unknown"
	}

	return &GeoInfo{
		CountryCode: city.Country.ISOCode,
		City:        cityName,
		ISP:         isp,
		IP:          ipStr,
	}
}

// AutoDownload downloads GeoLite2 databases if they don't exist.
func AutoDownload(dir, licenseKey string) error {
	if licenseKey == "" {
		return fmt.Errorf("MAXMIND_LICENSE_KEY not set")
	}

	cityPath := filepath.Join(dir, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(dir, "GeoLite2-ASN.mmdb")

	if fileExists(cityPath) && fileExists(asnPath) {
		return nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	baseURL := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?license_key=%s&edition_id=", licenseKey)

	if !fileExists(cityPath) {
		log.Printf("[geoip] downloading GeoLite2-City...")
		if err := downloadAndExtract(baseURL+"GeoLite2-City&suffix=tar.gz", dir, "GeoLite2-City.mmdb"); err != nil {
			return fmt.Errorf("download city db: %w", err)
		}
	}

	if !fileExists(asnPath) {
		log.Printf("[geoip] downloading GeoLite2-ASN...")
		if err := downloadAndExtract(baseURL+"GeoLite2-ASN&suffix=tar.gz", dir, "GeoLite2-ASN.mmdb"); err != nil {
			return fmt.Errorf("download asn db: %w", err)
		}
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func downloadAndExtract(url, dir, targetFile string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == targetFile {
			outPath := filepath.Join(dir, targetFile)
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("create %s: %w", outPath, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write %s: %w", outPath, err)
			}
			f.Close()
			log.Printf("[geoip] extracted %s (%d bytes)", targetFile, hdr.Size)
			return nil
		}
	}

	return fmt.Errorf("%s not found in archive", targetFile)
}
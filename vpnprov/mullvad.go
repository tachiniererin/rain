package vpnprov

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/rain/internal/logger"
)

var log = logger.New("mullvad")

type mullvadAccount struct {
	Token       string    `json:"token"`
	PrettyToken string    `json:"pretty_token"`
	Active      bool      `json:"active"`
	Expires     time.Time `json:"expires"`
	ExpiryUnix  int       `json:"expiry_unix"`
	Ports       []int     `json:"ports"`
	CityPorts   []struct {
		Port     int    `json:"port"`
		CityCode string `json:"city_code"`
		WgKey    string `json:"wgkey"`
	} `json:"city_ports"`
	MaxPorts    int           `json:"max_ports"`
	CanAddPorts bool          `json:"can_add_ports"`
	WgPeers     []interface{} `json:"wg_peers"`
	// rest omitted for now
}

type mullvadLogin struct {
	AuthToken string         `json:"auth_token"`
	Account   mullvadAccount `json:"account"`
}

type mullvadRemovePort struct {
	Port     int    `json:"port"`
	CityCode string `json:"city_code"`
}

type mullvadAddPort struct {
	PubKey   string `json:"pubkey"`
	CityCode string `json:"city_code"`
}

type mullvadAddedPort struct {
	Port int `json:"port"`
}

type mullvadStatus struct {
	// other fields currently omitted
	ExitHostname string `json:"mullvad_exit_ip_hostname"`
}

type mullvadRelay struct {
	Hostname    string `json:"hostname"`
	CountryCode string `json:"country_code"`
	CityCode    string `json:"city_code"`
}

type MullvadSession struct {
	ID          string
	PubKey      string
	Client      *http.Client
	authToken   string
	account     mullvadAccount
	currentCity string
	login       time.Time
}

func (s *MullvadSession) refresh() error {
	req, _ := http.NewRequest(http.MethodGet, "https://api-www.mullvad.net/www/me", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.authToken))
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh error, status %d", resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&s.account); err != nil {
		return err
	}

	return nil
}

func (s *MullvadSession) Login() error {
	url := fmt.Sprintf("https://api-www.mullvad.net/www/accounts/%s/", s.ID)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/json")

	log.Info("sending login request")
	t := time.Now()
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}

	log.Infof("login took %v", time.Since(t))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login error, status %d", resp.StatusCode)
	}

	var login mullvadLogin

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&login); err != nil {
		return err
	}

	s.account = login.Account
	s.authToken = login.AuthToken

	var relays []mullvadRelay

	req, _ = http.NewRequest(http.MethodGet, "https://api-www.mullvad.net/www/relays/all/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.authToken))
	resp, err = s.Client.Get("https://api-www.mullvad.net/www/relays/all/")
	if err != nil {
		return err
	}

	dec = json.NewDecoder(resp.Body)
	if err := dec.Decode(&relays); err != nil {
		return err
	}

	var status mullvadStatus

	log.Info("requesting am.i.mullvad")
	t = time.Now()
	resp, err = s.Client.Get("https://ipv4.am.i.mullvad.net/json")
	if err != nil {
		return err
	}

	log.Infof("status request took %v", time.Since(t))

	dec = json.NewDecoder(resp.Body)
	if err := dec.Decode(&status); err != nil {
		return err
	}

	// extract the current city from the mullvad status api
	for _, relay := range relays {
		if relay.Hostname == status.ExitHostname {
			s.currentCity = fmt.Sprintf("%s-%s", relay.CountryCode, relay.CityCode)
			break
		}
	}

	log.Infof("current city: %s", s.currentCity)

	// remove all forwarded ports of this city with our pub key, in case a previous instance left something behind
	for _, port := range s.account.CityPorts {
		if port.WgKey == s.PubKey {
			if err := s.RemoveForward(port.Port); err != nil {
				return err
			}
		}
	}

	// refresh account data, now there should be some more free port forwards
	if err := s.refresh(); err != nil {
		return err
	}

	s.login = time.Now()

	return nil
}

func (s *MullvadSession) RemoveForward(port int) error {
	if time.Since(s.login) > time.Hour {
		if err := s.Login(); err != nil {
			return err
		}
	}

	b, err := json.Marshal(mullvadRemovePort{Port: port, CityCode: s.currentCity})
	if err != nil {
		return err
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api-www.mullvad.net/www/ports/remove/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.authToken))
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("remove port forward error, status %d", resp.StatusCode)
	}

	return nil
}

func (s *MullvadSession) AddForward() (int, error) {
	if time.Since(s.login) > time.Hour {
		if err := s.Login(); err != nil {
			return 0, err
		}
	}

	b, err := json.Marshal(mullvadAddPort{PubKey: s.PubKey, CityCode: s.currentCity})
	if err != nil {
		return 0, err
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api-www.mullvad.net/www/ports/add/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.authToken))

	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Infof("response: %s", string(body))
		return 0, fmt.Errorf("add port forward error, status %d", resp.StatusCode)
	}

	var portForward mullvadAddedPort

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&portForward); err != nil {
		return 0, err
	}

	return portForward.Port, nil
}

package country

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Status string

const (
	Unknown   Status = "UNKNOWN"
	Confirmed Status = "CONFIRMED"
	Conflict  Status = "CONFLICT"
)

type Observation struct {
	IP      netip.Addr
	Country string
}

func (o Observation) Valid() bool {
	return o.IP.IsValid() && IsCode(o.Country)
}

type FamilyResult struct {
	Available        bool
	IP               netip.Addr
	Country          string
	ObservedCountry  string
	Status           Status
	CandidateCountry string
	CandidateCount   int
	ConfirmedAt      time.Time
	ObservedAt       time.Time
}

type RouteCountries struct {
	DirectV4 FamilyResult
	DirectV6 FamilyResult
	WarpV4   FamilyResult
	WarpV6   FamilyResult
}

type Decision struct {
	Include  bool
	Filtered bool
	Unknown  int
	Conflict int
}

func ParseCodes(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			code := strings.ToUpper(strings.TrimSpace(part))
			if code == "" {
				continue
			}
			if !IsCode(code) {
				return nil, fmt.Errorf("invalid country code %q", part)
			}
			result[code] = struct{}{}
		}
	}
	return result, nil
}

func Observe(previous FamilyResult, observation Observation, now time.Time) FamilyResult {
	if !observation.Valid() {
		return previous
	}

	code := strings.ToUpper(observation.Country)
	previous.Available = true
	previous.IP = observation.IP
	previous.ObservedCountry = code
	previous.ObservedAt = now

	if previous.Country == "" || previous.Status == Unknown {
		previous.Country = code
		previous.Status = Confirmed
		previous.ConfirmedAt = now
		previous.CandidateCountry = ""
		previous.CandidateCount = 0
		return previous
	}

	if code == previous.Country {
		previous.Status = Confirmed
		previous.CandidateCountry = ""
		previous.CandidateCount = 0
		return previous
	}

	if previous.CandidateCountry == code {
		previous.CandidateCount++
	} else {
		previous.CandidateCountry = code
		previous.CandidateCount = 1
	}
	if previous.CandidateCount >= 2 {
		previous.Country = code
		previous.Status = Confirmed
		previous.ConfirmedAt = now
		previous.CandidateCountry = ""
		previous.CandidateCount = 0
		return previous
	}
	previous.Status = Conflict
	return previous
}

func Apply(route RouteCountries, warp bool, observation Observation, now time.Time) RouteCountries {
	if !observation.Valid() {
		return route
	}
	if warp {
		if observation.IP.Is4() {
			route.WarpV4 = Observe(route.WarpV4, observation, now)
		} else {
			route.WarpV6 = Observe(route.WarpV6, observation, now)
		}
		return route
	}
	if observation.IP.Is4() {
		route.DirectV4 = Observe(route.DirectV4, observation, now)
	} else {
		route.DirectV6 = Observe(route.DirectV6, observation, now)
	}
	return route
}

func Filter(route RouteCountries, warp bool, excluded map[string]struct{}) Decision {
	if len(excluded) == 0 {
		return Decision{Include: true}
	}
	families := []FamilyResult{route.DirectV4, route.DirectV6}
	if warp {
		families = []FamilyResult{route.WarpV4, route.WarpV6}
	}

	available := 0
	decision := Decision{}
	for _, family := range families {
		if !family.Available {
			continue
		}
		available++
		if _, found := excluded[family.Country]; found {
			decision.Filtered = true
		}
		if _, found := excluded[family.ObservedCountry]; found {
			decision.Filtered = true
		}
		if _, found := excluded[family.CandidateCountry]; found {
			decision.Filtered = true
		}
		switch family.Status {
		case Confirmed:
			if family.Country == "" {
				decision.Unknown = 1
			}
		case Conflict:
			decision.Conflict = 1
		default:
			decision.Unknown = 1
		}
	}
	if available == 0 {
		decision.Unknown = 1
	}
	decision.Include = !decision.Filtered && decision.Unknown == 0 && decision.Conflict == 0
	return decision
}

func IsCode(code string) bool {
	_, ok := isoAlpha2[strings.ToUpper(strings.TrimSpace(code))]
	return ok
}

var isoAlpha2 = func() map[string]struct{} {
	const codes = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"
	result := make(map[string]struct{}, 249)
	for _, code := range strings.Fields(codes) {
		result[code] = struct{}{}
	}
	return result
}()

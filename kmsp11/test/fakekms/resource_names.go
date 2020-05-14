package fakekms

import (
	"fmt"
	"regexp"
)

const idPattern = "[a-zA-Z0-9_-]{1,63}"

var (
	idRegexp        = regexp.MustCompile(fmt.Sprintf("^%s$", idPattern))
	locationRegexp  = regexp.MustCompile("^projects/([^/]+)/locations/([^/]+)$")
	keyRingRegexp   = regexp.MustCompile(fmt.Sprintf("^(.*)/keyRings/(%s)$", idPattern))
	cryptoKeyRegexp = regexp.MustCompile(fmt.Sprintf("^(.*)/cryptoKeys/(%s)$", idPattern))
)

// checkID returns InvalidArgument if the provided ID does not comply with the KMS
// ID naming rules.
func checkID(id string) error {
	if !idRegexp.MatchString(id) {
		return errInvalidArgument("invalid id: %s", id)
	}
	return nil
}

type locationName struct {
	ProjectID, LocationID string
}

func parseLocationName(name string) (locationName, error) {
	if m := locationRegexp.FindStringSubmatch(name); m != nil {
		return locationName{ProjectID: m[1], LocationID: m[2]}, nil
	}
	return locationName{}, errMalformedName("location", name)
}

func (n locationName) Project() string {
	return fmt.Sprintf("projects/%s", n.ProjectID)
}

func (n locationName) Location() string {
	return fmt.Sprintf("projects/%s/locations/%s", n.ProjectID, n.LocationID)
}

func (n locationName) String() string {
	return n.Location()
}

type keyRingName struct {
	locationName
	KeyRingID string
}

func parseKeyRingName(name string) (keyRingName, error) {
	if m := keyRingRegexp.FindStringSubmatch(name); m != nil {
		if loc, err := parseLocationName(m[1]); err == nil {
			return keyRingName{locationName: loc, KeyRingID: m[2]}, nil
		}
	}
	return keyRingName{}, errMalformedName("key ring", name)
}

func (n keyRingName) KeyRing() string {
	return fmt.Sprintf("%s/keyRings/%s", n.Location(), n.KeyRingID)
}

func (n keyRingName) String() string {
	return n.KeyRing()
}

type cryptoKeyName struct {
	keyRingName
	CryptoKeyID string
}

func parseCryptoKeyName(name string) (cryptoKeyName, error) {
	if m := cryptoKeyRegexp.FindStringSubmatch(name); m != nil {
		if kr, err := parseKeyRingName(m[1]); err == nil {
			return cryptoKeyName{keyRingName: kr, CryptoKeyID: m[2]}, nil
		}
	}
	return cryptoKeyName{}, errMalformedName("crypto key", name)
}

func (n cryptoKeyName) CryptoKey() string {
	return fmt.Sprintf("%s/cryptoKeys/%s", n.KeyRing(), n.CryptoKeyID)
}

func (n cryptoKeyName) String() string {
	return n.CryptoKey()
}

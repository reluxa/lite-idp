package idp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

//LogoutResponse holds the data which is used to create the LogoutResponse SAML2 message
type LogoutResponse struct {
	EntityID   string
	OriginalID string
	RelayState string
}

func (i *IDP) createLogoutResponseRedirect(logoutResponse *LogoutResponse, w http.ResponseWriter, r *http.Request) error {
	sp := i.sps[logoutResponse.EntityID]
	location := sp.SingleLogoutServices[0].Location

	data := struct {
		ID         string
		OriginalID string
		Time       string
		Issuer     string
		Destination string
	}{
		uuid.New().String(),
		logoutResponse.OriginalID,
		time.Now().Format(time.RFC3339),
		i.entityID,
		location,
	}

	templ, err := template.New("logoutResponse").Parse(logoutResponseTemplate)
	if err != nil {
		return err
	}

	log.Info("redirect url was location: " + location)

	var b bytes.Buffer
	writer, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		return err
	}
	err = templ.Execute(writer, data)
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}

	samlRequest := url.QueryEscape(base64.StdEncoding.EncodeToString(b.Bytes()))
	requestToSign := "SAMLResponse=" + samlRequest + "&RelayState=" + logoutResponse.RelayState + "&SigAlg=" + url.QueryEscape(i.signer.Algorithm())

	signature, err := i.signer.Sign([]byte(requestToSign))
	if err != nil {
		return err
	}
	query := requestToSign + "&Signature=" + url.QueryEscape(signature)

	log.Info("redirect url was calculated: " + query)

	http.SetCookie(w, &http.Cookie{
		Name:     i.cookieName,
		Path:     "/",
		Value:    "",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-100 * time.Hour),
	})
	http.Redirect(w, r, location+"?"+query, 302)
	return nil
}

const logoutResponseTemplate = `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
 ID="{{ .ID }}"
InResponseTo="{{ .OriginalID }}"
 IssueInstant="{{ .Time }}" Version="2.0" Destination="{{ .Destination }}">
 <Issuer>{{ .Issuer }}</Issuer>
 <samlp:Status>
 <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
 </samlp:Status>
</samlp:LogoutResponse>`

package engine

import (
	"net/http"
	"strings"
	"time"
)

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func collectCapturedBaseline(prepared []preparedRequest, actors []Actor, cfg Config) ([]Observation, map[string]accessRecord) {
	obs := make([]Observation, 0, len(prepared)*len(actors))
	access := map[string]accessRecord{}
	for _, p := range prepared {
		if !mimeAllowed(p.Item.Mimetype, cfg.FilterMimeTypes) {
			continue
		}
		rawResp, _ := DecodeBurpRequest(p.Item.Response)
		body := rawResp
		if body == "" {
			body = p.Item.Response
		}
		status := p.Item.Status
		if status == 0 {
			status = 200
		}
		fp := capturedFingerprint(status, body)
		actor := matchCapturedActor(p.Req.Headers, actors)
		if actor.Name == "" {
			continue
		}
		allowed := inferAllowed(fp, cfg.DenyStatuses)
		o := Observation{Actor: actor, URL: p.Req.URL, Endpoint: EndpointSignature(p.Req.Method, p.Req.URL, p.Refs), Method: p.Req.Method, Action: InferAction(p.Req.Method, p.Req.URL), Objects: p.Refs, Fingerprint: fp, Allowed: &allowed, Timestamp: time.Now().UTC(), RequestBody: p.Req.Body, Evidence: "offline plan mode: observation derived from Burp capture"}
		obs = append(obs, o)
		access[accessKey(actor.Name, o.Endpoint, p.Refs)] = accessRecord{Observation: o, Body: body}
	}
	return obs, access
}

func matchCapturedActor(h map[string]string, actors []Actor) Actor {
	for _, a := range actors {
		for k, v := range a.Headers {
			for hk, hv := range h {
				if strings.EqualFold(k, hk) && v == hv {
					return a
				}
			}
		}
	}
	return Actor{}
}

func capturedFingerprint(status int, body string) ResponseFingerprint {
	h := make(http.Header)
	return FingerprintBytes(status, h, nil, 0, []byte(body))
}

package engine

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"sort"
)

type BurpItem struct {
	URL            string `xml:"url"`
	Method         string `xml:"method"`
	Extension      string `xml:"extension"`
	Request        string `xml:"request"`
	Mimetype       string `xml:"mimetype"`
	Response       string `xml:"response"`
	Status         int    `xml:"status"`
	ResponseLength string `xml:"responselength"`
}

type burpItems struct {
	Item []BurpItem `xml:"item"`
}

func ReadBurpXML(filename string) ([]BurpItem, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read Burp XML: %w", err)
	}
	var out burpItems
	if err := xml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse Burp XML: %w", err)
	}
	return out.Item, nil
}

func DecodeBurpRequest(s string) (string, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	return "", fmt.Errorf("request is not valid base64")
}

func ListMimeTypes(items []BurpItem) []string {
	set := map[string]bool{}
	for _, item := range items {
		if item.Mimetype != "" {
			set[item.Mimetype] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

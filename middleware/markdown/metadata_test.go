package markdown

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func check(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

var TOML = [5]string{`
title = "A title"
template = "default"
name = "value"
positive = true
negative = false
`,
	`+++
title = "A title"
template = "default"
name = "value"
positive = true
negative = false
+++
Page content
	`,
	`+++
title = "A title"
template = "default"
name = "value"
positive = true
negative = false
	`,
	`title = "A title" template = "default" [variables] name = "value"`,
	`+++
title = "A title"
template = "default"
name = "value"
positive = true
negative = false
+++
`,
}

var YAML = [5]string{`
title : A title
template : default
name : value
positive : true
negative : false
`,
	`---
title : A title
template : default
name : value
positive : true
negative : false
---
	Page content
	`,
	`---
title : A title
template : default
name : value
	`,
	`title : A title template : default variables : name : value : positive : true : negative : false`,
	`---
title : A title
template : default
name : value
positive : true
negative : false
---
`,
}

var JSON = [5]string{`
	"title" : "A title",
	"template" : "default",
	"name" : "value",
	"positive" : true,
	"negative" : false
`,
	`{
	"title" : "A title",
	"template" : "default",
	"name" : "value",
	"positive" : true,
	"negative" : false
}
Page content
	`,
	`
{
	"title" : "A title",
	"template" : "default",
	"name" : "value",
	"positive" : true,
	"negative" : false
	`,
	`
{
	"title" :: "A title",
	"template" : "default",
	"name" : "value",
	"positive" : true,
	"negative" : false
}
	`,
	`{
	"title" : "A title",
	"template" : "default",
	"name" : "value",
	"positive" : true,
	"negative" : false
}
`,
}

func TestParsers(t *testing.T) {
	expected := Metadata{
		Title:    "A title",
		Template: "default",
		Variables: map[string]string{
			"name":     "value",
			"title":    "A title",
			"template": "default",
		},
		Flags: map[string]bool{
			"positive": true,
			"negative": false,
		},
	}
	compare := func(m Metadata) bool {
		if m.Title != expected.Title {
			return false
		}
		if m.Template != expected.Template {
			return false
		}
		for k, v := range m.Variables {
			if v != expected.Variables[k] {
				return false
			}
		}
		for k, v := range m.Flags {
			if v != expected.Flags[k] {
				return false
			}
		}
		varLenOK := len(m.Variables) == len(expected.Variables)
		flagLenOK := len(m.Flags) == len(expected.Flags)
		return varLenOK && flagLenOK
	}

	data := []struct {
		parser   MetadataParser
		testData [5]string
		name     string
	}{
		{&JSONMetadataParser{metadata: newMetadata()}, JSON, "json"},
		{&YAMLMetadataParser{metadata: newMetadata()}, YAML, "yaml"},
		{&TOMLMetadataParser{metadata: newMetadata()}, TOML, "toml"},
	}

	for _, v := range data {
		// metadata without identifiers
		if _, err := v.parser.Parse([]byte(v.testData[0])); err == nil {
			t.Fatalf("Expected error for invalid metadata for %v", v.name)
		}

		// metadata with identifiers
		md, err := v.parser.Parse([]byte(v.testData[1]))
		check(t, err)
		if !compare(v.parser.Metadata()) {
			t.Fatalf("Expected %v, found %v for %v", expected, v.parser.Metadata(), v.name)
		}
		if "Page content" != strings.TrimSpace(string(md)) {
			t.Fatalf("Expected %v, found %v for %v", "Page content", string(md), v.name)
		}

		var line []byte
		fmt.Fscanln(bytes.NewReader([]byte(v.testData[1])), &line)
		if parser := findParser(line); parser == nil {
			t.Fatalf("Parser must be found for %v", v.name)
		} else {
			if reflect.TypeOf(parser) != reflect.TypeOf(v.parser) {
				t.Fatalf("parsers not equal. %v != %v", reflect.TypeOf(parser), reflect.TypeOf(v.parser))
			}
		}

		// metadata without closing identifier
		if _, err := v.parser.Parse([]byte(v.testData[2])); err == nil {
			t.Fatalf("Expected error for missing closing identifier for %v", v.name)
		}

		// invalid metadata
		if md, err = v.parser.Parse([]byte(v.testData[3])); err == nil {
			t.Fatalf("Expected error for invalid metadata for %v", v.name)
		}

		// front matter but no body
		if md, err = v.parser.Parse([]byte(v.testData[4])); err != nil {
			t.Fatalf("Unexpected error for valid metadata but no body for %v", v.name)
		}
	}

}

func TestLargeBody(t *testing.T) {
	var JSON = `{
"template": "chapter"
}

Mycket olika byggnader har man i de nordiska rikena: pyramidformiga, kilformiga, välvda, runda och fyrkantiga. De pyramidformiga består helt enkelt av träribbor, som upptill löper samman och nedtill bildar en vidare krets; de är avsedda att användas av hantverkarna under sommaren, för att de inte ska plågas av solen, på samma gång som de besväras av rök och eld. De kilformiga husen är i regel försedda med höga tak, för att de täta och tunga snömassorna fortare ska kunna blåsa av och inte tynga ned taken. Dessa är täckta av björknäver, tegel eller kluvet spån av furu - för kådans skull -, gran, ek eller bok; taken på de förmögnas hus däremot med plåtar av koppar eller bly, i likhet med kyrktaken. Valvbyggnaderna uppförs ganska konstnärligt till skydd mot våldsamma vindar och snöfall, görs av sten eller trä, och är avsedda för olika alldagliga viktiga ändamål. Liknande byggnader kan finnas i stormännens gårdar där de används som förvaringsrum för husgeråd och jordbruksredskap. De runda byggnaderna - som för övrigt är de högst sällsynta - används av konstnärer, som vid sitt arbete behöver ett jämnt fördelat ljus från taket. Vanligast är de fyrkantiga husen, vars grova bjälkar är synnerligen väl hopfogade i hörnen - ett sant mästerverk av byggnadskonst; även dessa har fönster högt uppe i taken, för att dagsljuset skall kunna strömma in och ge alla därinne full belysning. Stenhusen har dörröppningar i förhållande till byggnadens storlek, men smala fönstergluggar, som skydd mot den stränga kölden, frosten och snön. Vore de större och vidare, såsom fönstren i Italien, skulle husen i följd av den fint yrande snön, som röres upp av den starka blåsten, precis som dammet av virvelvinden, snart nog fyllas med massor av snö och inte kunna stå emot dess tryck, utan störta samman.

	`
	var TOML = `+++
template = "chapter"
+++

Mycket olika byggnader har man i de nordiska rikena: pyramidformiga, kilformiga, välvda, runda och fyrkantiga. De pyramidformiga består helt enkelt av träribbor, som upptill löper samman och nedtill bildar en vidare krets; de är avsedda att användas av hantverkarna under sommaren, för att de inte ska plågas av solen, på samma gång som de besväras av rök och eld. De kilformiga husen är i regel försedda med höga tak, för att de täta och tunga snömassorna fortare ska kunna blåsa av och inte tynga ned taken. Dessa är täckta av björknäver, tegel eller kluvet spån av furu - för kådans skull -, gran, ek eller bok; taken på de förmögnas hus däremot med plåtar av koppar eller bly, i likhet med kyrktaken. Valvbyggnaderna uppförs ganska konstnärligt till skydd mot våldsamma vindar och snöfall, görs av sten eller trä, och är avsedda för olika alldagliga viktiga ändamål. Liknande byggnader kan finnas i stormännens gårdar där de används som förvaringsrum för husgeråd och jordbruksredskap. De runda byggnaderna - som för övrigt är de högst sällsynta - används av konstnärer, som vid sitt arbete behöver ett jämnt fördelat ljus från taket. Vanligast är de fyrkantiga husen, vars grova bjälkar är synnerligen väl hopfogade i hörnen - ett sant mästerverk av byggnadskonst; även dessa har fönster högt uppe i taken, för att dagsljuset skall kunna strömma in och ge alla därinne full belysning. Stenhusen har dörröppningar i förhållande till byggnadens storlek, men smala fönstergluggar, som skydd mot den stränga kölden, frosten och snön. Vore de större och vidare, såsom fönstren i Italien, skulle husen i följd av den fint yrande snön, som röres upp av den starka blåsten, precis som dammet av virvelvinden, snart nog fyllas med massor av snö och inte kunna stå emot dess tryck, utan störta samman.

	`
	var YAML = `---
template : chapter
---

Mycket olika byggnader har man i de nordiska rikena: pyramidformiga, kilformiga, välvda, runda och fyrkantiga. De pyramidformiga består helt enkelt av träribbor, som upptill löper samman och nedtill bildar en vidare krets; de är avsedda att användas av hantverkarna under sommaren, för att de inte ska plågas av solen, på samma gång som de besväras av rök och eld. De kilformiga husen är i regel försedda med höga tak, för att de täta och tunga snömassorna fortare ska kunna blåsa av och inte tynga ned taken. Dessa är täckta av björknäver, tegel eller kluvet spån av furu - för kådans skull -, gran, ek eller bok; taken på de förmögnas hus däremot med plåtar av koppar eller bly, i likhet med kyrktaken. Valvbyggnaderna uppförs ganska konstnärligt till skydd mot våldsamma vindar och snöfall, görs av sten eller trä, och är avsedda för olika alldagliga viktiga ändamål. Liknande byggnader kan finnas i stormännens gårdar där de används som förvaringsrum för husgeråd och jordbruksredskap. De runda byggnaderna - som för övrigt är de högst sällsynta - används av konstnärer, som vid sitt arbete behöver ett jämnt fördelat ljus från taket. Vanligast är de fyrkantiga husen, vars grova bjälkar är synnerligen väl hopfogade i hörnen - ett sant mästerverk av byggnadskonst; även dessa har fönster högt uppe i taken, för att dagsljuset skall kunna strömma in och ge alla därinne full belysning. Stenhusen har dörröppningar i förhållande till byggnadens storlek, men smala fönstergluggar, som skydd mot den stränga kölden, frosten och snön. Vore de större och vidare, såsom fönstren i Italien, skulle husen i följd av den fint yrande snön, som röres upp av den starka blåsten, precis som dammet av virvelvinden, snart nog fyllas med massor av snö och inte kunna stå emot dess tryck, utan störta samman.

	`
	var expectedBody = `Mycket olika byggnader har man i de nordiska rikena: pyramidformiga, kilformiga, välvda, runda och fyrkantiga. De pyramidformiga består helt enkelt av träribbor, som upptill löper samman och nedtill bildar en vidare krets; de är avsedda att användas av hantverkarna under sommaren, för att de inte ska plågas av solen, på samma gång som de besväras av rök och eld. De kilformiga husen är i regel försedda med höga tak, för att de täta och tunga snömassorna fortare ska kunna blåsa av och inte tynga ned taken. Dessa är täckta av björknäver, tegel eller kluvet spån av furu - för kådans skull -, gran, ek eller bok; taken på de förmögnas hus däremot med plåtar av koppar eller bly, i likhet med kyrktaken. Valvbyggnaderna uppförs ganska konstnärligt till skydd mot våldsamma vindar och snöfall, görs av sten eller trä, och är avsedda för olika alldagliga viktiga ändamål. Liknande byggnader kan finnas i stormännens gårdar där de används som förvaringsrum för husgeråd och jordbruksredskap. De runda byggnaderna - som för övrigt är de högst sällsynta - används av konstnärer, som vid sitt arbete behöver ett jämnt fördelat ljus från taket. Vanligast är de fyrkantiga husen, vars grova bjälkar är synnerligen väl hopfogade i hörnen - ett sant mästerverk av byggnadskonst; även dessa har fönster högt uppe i taken, för att dagsljuset skall kunna strömma in och ge alla därinne full belysning. Stenhusen har dörröppningar i förhållande till byggnadens storlek, men smala fönstergluggar, som skydd mot den stränga kölden, frosten och snön. Vore de större och vidare, såsom fönstren i Italien, skulle husen i följd av den fint yrande snön, som röres upp av den starka blåsten, precis som dammet av virvelvinden, snart nog fyllas med massor av snö och inte kunna stå emot dess tryck, utan störta samman.
`
	data := []struct {
		parser   MetadataParser
		testData string
		name     string
	}{
		{&JSONMetadataParser{metadata: newMetadata()}, JSON, "json"},
		{&YAMLMetadataParser{metadata: newMetadata()}, YAML, "yaml"},
		{&TOMLMetadataParser{metadata: newMetadata()}, TOML, "toml"},
	}
	for _, v := range data {
		// metadata without identifiers
		if md, err := v.parser.Parse([]byte(v.testData)); err != nil || strings.TrimSpace(string(md)) != strings.TrimSpace(expectedBody) {
			t.Fatalf("Error not expected and/or markdown not equal for %v", v.name)
		}
	}
}

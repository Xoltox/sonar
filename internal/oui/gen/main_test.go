package main

import "testing"

func TestShortName(t *testing.T) {
	cases := map[string]string{
		"MICRO-STAR INTERNATIONAL CO.,LTD.":                 "Micro-Star",
		"Apple, Inc.":                                       "Apple",
		"TP-LINK TECHNOLOGIES CO.,LTD.":                     "TP-Link",
		"Raspberry Pi Trading Ltd":                          "Raspberry Pi",
		"Samsung Electronics Co.,Ltd":                       "Samsung",
		"Intel Corporate":                                   "Intel",
		"HUAWEI TECHNOLOGIES CO.,LTD":                       "Huawei",
		"Hewlett Packard Enterprise":                        "HPE",
		"Hon Hai Precision Ind. Co.,Ltd.":                   "Foxconn",
		"LG Electronics (Mobile Communications)":            "LG",
		"Acme Widgets Inc.":                                 "Acme Widgets",
		"SOMEVENDOR GMBH":                                   "Somevendor",
		"Systems":                                           "Systems",
		"  Foo   Bar   Group, Ltd. ":                        "Foo Bar",
		"Dell Inc.":                                         "Dell",
		"vivo Mobile Communication Co., Ltd.":               "vivo",
		"Guangdong Oppo Mobile Telecommunications Corp.":    "OPPO",
		"Hangzhou Hikvision Digital Technology Co.,Ltd.":    "Hikvision",
		"Beijing Xiaomi Mobile Software Co., Ltd":           "Xiaomi",
		"Tietech.Co":                                        "Tietech",
		"Hanyang Digitech Co.Ltd":                           "Hanyang Digitech",
		"Honeywell Co. Ltd. (KORE":                          "Honeywell",
		"Harbour Networks Ltd. Co":                          "Harbour",
		"Ophit Co.Ltd":                                      "Ophit",
		"TEAC Corp. R& D":                                   "TEAC",
		"Arcor AG&Co":                                       "Arcor",
		"AT&T Wireless":                                     "AT&T Wireless",
		"shenzhen phoenix telecom":                          "Phoenix",
		"Hong Kong Foo Widgets Ltd":                         "Foo Widgets",
		"Shenzhen":                                          "Shenzhen",
		"Micro-Star Foo":                                    "Micro-Star",
		"Mobile":                                            "Mobile",
		"ASUSTek COMPUTER INC.":                             "ASUS",
		"LCFC(HeFei) Electronics Technology co., ltd":       "Lenovo",
		"CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.":      "Foxconn",
		"Texas Instruments":                                 "TI",
		"Universal Global Scientific Industrial Co., Ltd.":  "USI",
		"Amazon Technologies Inc.":                          "Amazon",
		"Nest Labs Inc.":                                    "Google Nest",
		"Ring LLC":                                          "Ring",
		"Sony Interactive Entertainment Inc.":               "Sony",
		"LG Innotek":                                        "LG",
		"Routerboard.com":                                   "MikroTik",
		"Lite-On Technology Corp.":                          "Lite-On",
		"Hewlett Packard":                                   "HP",
		"Alpha Beta Gamma Delta Epsilon":                    "Alpha Beta Gamma",
		"Averyveryverylongwordone Averyveryverylongwordtwo": "Averyveryverylongwordone",
	}
	for in, want := range cases {
		if got := shortName(in); got != want {
			t.Errorf("shortName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := shortName("A very long vendor name that goes on and on"); len([]rune(got)) > 24 || got != "A very long" {
		t.Errorf("long: %q", got)
	}
	if got := shortName("Foo \u2014 Bar"); got != "Foo - Bar" {
		t.Errorf("dash: %q", got)
	}
}

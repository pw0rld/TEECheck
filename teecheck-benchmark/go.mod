module github.com/pw0rld/TEECheck/teecheck-benchmark

go 1.25.0

require github.com/pw0rld/TEECheck/tee-usage-scanner v0.0.0

require (
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pw0rld/TEECheck/tee-usage-scanner => ../tee-usage-scanner

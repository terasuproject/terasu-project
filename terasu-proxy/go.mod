module terasu-proxy

go 1.21

// 依赖通过 import 引入；构建时请固定 github.com/fumiama/terasu 的版本。
require (
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/net v0.24.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/fumiama/terasu v0.0.0-20251006080703-541b84ca4a5f

require (
	github.com/FloatTech/ttl v0.0.0-20250224045156-012b1463287d // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

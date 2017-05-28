package units

// Base2Bytes is the old non-SI power-of-2 byte scale (1024 bytes in a kilobyte,
// etc.).
type Base2Bytes int64

// Base-2 byte units.
const (
	Kibibyte Base2Bytes = 1024
	KiB                 = Kibibyte
	Mebibyte            = Kibibyte * 1024
	MiB                 = Mebibyte
	Gibibyte            = Mebibyte * 1024
	GiB                 = Gibibyte
	Tebibyte            = Gibibyte * 1024
	TiB                 = Tebibyte
	Pebibyte            = Tebibyte * 1024
	PiB                 = Pebibyte
	Exbibyte            = Pebibyte * 1024
	EiB                 = Exbibyte
)

var (
	bytesUnitMap    = MakeUnitMap("iB", "B", 1024)
	oldBytesUnitMap = MakeUnitMap("B", "B", 1024)
)

// ParseBase2Bytes supports both iB and B in base-2 multipliers. That is, KB
// and KiB are both 1024.
func ParseBase2Bytes(s string) (Base2Bytes, error) {
	n, err := ParseUnit(s, bytesUnitMap)
	if err != nil {
		n, err = ParseUnit(s, oldBytesUnitMap)
	}
	return Base2Bytes(n), err
}

func (b Base2Bytes) String() string {
	return ToString(int64(b), 1024, "iB", "B")
}

var (
	metricBytesUnitMap = MakeUnitMap("B", "B", 1000)
)

// MetricBytes are SI byte units (1000 bytes in a kilobyte).
type MetricBytes SI

// SI base-10 byte units.
const (
	Kilobyte MetricBytes = 1000
	KB                   = Kilobyte
	Megabyte             = Kilobyte * 1000
	MB                   = Megabyte
	Gigabyte             = Megabyte * 1000
	GB                   = Gigabyte
	Terabyte             = Gigabyte * 1000
	TB                   = Terabyte
	Petabyte             = Terabyte * 1000
	PB                   = Petabyte
	Exabyte              = Petabyte * 1000
	EB                   = Exabyte
)

// ParseMetricBytes parses base-10 metric byte units. That is, KB is 1000 bytes.
func ParseMetricBytes(s string) (MetricBytes, error) {
	n, err := ParseUnit(s, metricBytesUnitMap)
	return MetricBytes(n), err
}

func (m MetricBytes) String() string {
	return ToString(int64(m), 1000, "B", "B")
}

// ParseStrictBytes supports both iB and B suffixes for base 2 and metric,
// respectively. That is, KiB represents 1024 and KB represents 1000.
func ParseStrictBytes(s string) (int64, error) {
	n, err := ParseUnit(s, bytesUnitMap)
	if err != nil {
		n, err = ParseUnit(s, metricBytesUnitMap)
	}
	return int64(n), err
}

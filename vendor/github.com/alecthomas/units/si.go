package units

// SI units.
type SI int64

// SI unit multiples.
const (
	Kilo SI = 1000
	Mega    = Kilo * 1000
	Giga    = Mega * 1000
	Tera    = Giga * 1000
	Peta    = Tera * 1000
	Exa     = Peta * 1000
)

func MakeUnitMap(suffix, shortSuffix string, scale int64) map[string]float64 {
	return map[string]float64{
		shortSuffix:  1,
		"K" + suffix: float64(scale),
		"M" + suffix: float64(scale * scale),
		"G" + suffix: float64(scale * scale * scale),
		"T" + suffix: float64(scale * scale * scale * scale),
		"P" + suffix: float64(scale * scale * scale * scale * scale),
		"E" + suffix: float64(scale * scale * scale * scale * scale * scale),
	}
}

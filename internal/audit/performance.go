package audit

// Latency uses fixed logarithmic microsecond buckets (1 us through ~35 minutes).
// Percentiles are upper bounds, not interpolated exact values. Memory is bounded
// independently of traffic volume. Historical records without timing are excluded.
type Latency struct {
	Count      int64   `json:"count"`
	MeanUS     float64 `json:"mean_us"`
	MaxUS      int64   `json:"max_us"`
	P50UpperUS int64   `json:"p50_upper_us"`
	P95UpperUS int64   `json:"p95_upper_us"`
	buckets    [32]int64
}

func (s *Latency) observe(us int64) {
	s.Count++
	s.MeanUS += (float64(us) - s.MeanUS) / float64(s.Count)
	if us > s.MaxUS {
		s.MaxUS = us
	}
	s.buckets[Bucket(us)]++
	s.P50UpperUS = s.percentile(50)
	s.P95UpperUS = s.percentile(95)
}

// Bucket is the fixed logarithmic bucket for a duration in microseconds.
func Bucket(us int64) int {
	i := 0
	for i < 31 && us > int64(1)<<i {
		i++
	}
	return i
}

// LatencyFromBuckets rebuilds a summary from stored aggregates. The mean is
// sum/count, which can differ from the streaming mean in the last float digits.
func LatencyFromBuckets(count, sum, max int64, buckets [32]int64) Latency {
	s := Latency{Count: count, MaxUS: max, buckets: buckets}
	if count > 0 {
		s.MeanUS = float64(sum) / float64(count)
		s.P50UpperUS = s.percentile(50)
		s.P95UpperUS = s.percentile(95)
	}
	return s
}

func (s *Latency) percentile(p int64) int64 {
	target := (s.Count*p + 99) / 100
	var n int64
	for i, count := range s.buckets {
		n += count
		if n >= target {
			bound := int64(1) << i
			if bound > s.MaxUS || i == len(s.buckets)-1 {
				return s.MaxUS
			}
			return bound
		}
	}
	return 0
}

type Performance struct {
	TimedCalls  int64   `json:"timed_calls"`
	FailedCalls int64   `json:"failed_calls"`
	Handler     Latency `json:"handler"`
	Upstream    Latency `json:"upstream"`
	Gateway     Latency `json:"gateway"`
	// Capped reports that more calls match than an indexed store reads; the
	// total and these timings then cover the newest ones only.
	Capped bool `json:"-"`
}

func (s *Performance) observe(r Record) {
	if r.Timing == nil {
		return
	}
	s.TimedCalls++
	if r.Status != "ok" {
		s.FailedCalls++
	}
	s.Handler.observe(r.Timing.HandlerUS)
	s.Gateway.observe(r.Timing.GatewayUS)
	if r.Timing.Forwarded {
		s.Upstream.observe(r.Timing.UpstreamUS)
	}
}

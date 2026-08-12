package quality

import "time"

type State string

const (
	Healthy    State = "HEALTHY"
	Degraded   State = "DEGRADED"
	Dead       State = "DEAD"
	Recovering State = "RECOVERING"
)

type Observation string

const (
	Good      Observation = "GOOD"
	Partial   Observation = "PARTIAL"
	Blackhole Observation = "BLACKHOLE"
)

type StateConfig struct{ DeadCooldown time.Duration }

func DefaultStateConfig() StateConfig { return StateConfig{DeadCooldown: 30 * time.Minute} }

type RuntimeState struct {
	State                                  State
	ConsecutiveBlackholes, ConsecutiveGood int
	DeadAt                                 time.Time
}

func Transition(r RuntimeState, observation Observation, now time.Time, cfg StateConfig) RuntimeState {
	if r.State == "" {
		r.State = Healthy
	}
	switch r.State {
	case Healthy:
		if observation == Good {
			r.ConsecutiveBlackholes, r.ConsecutiveGood = 0, 0
		} else if observation == Partial {
			r.State, r.ConsecutiveGood = Degraded, 0
		} else {
			r.State, r.ConsecutiveBlackholes, r.ConsecutiveGood = Degraded, r.ConsecutiveBlackholes+1, 0
		}
	case Degraded:
		if observation == Good {
			r.ConsecutiveGood++
			r.ConsecutiveBlackholes = 0
			if r.ConsecutiveGood >= 2 {
				r.State, r.ConsecutiveGood = Healthy, 0
			}
		} else if observation == Partial {
			r.ConsecutiveGood = 0
		} else {
			r.ConsecutiveBlackholes++
			r.ConsecutiveGood = 0
			if r.ConsecutiveBlackholes >= 2 {
				r.State, r.DeadAt = Dead, now
			}
		}
	case Dead:
		if observation == Good && now.Sub(r.DeadAt) >= cfg.DeadCooldown {
			r.State, r.ConsecutiveGood = Recovering, 1
		} else if observation != Good {
			r.ConsecutiveGood = 0
		}
	case Recovering:
		if observation == Good {
			r.ConsecutiveGood++
			if r.ConsecutiveGood >= 2 {
				r.State, r.ConsecutiveGood = Healthy, 0
			}
		} else if observation == Partial {
			r.State, r.ConsecutiveGood = Degraded, 0
		} else {
			r.State, r.DeadAt, r.ConsecutiveGood = Dead, now, 0
		}
	}
	return r
}

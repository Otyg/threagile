package support

import (
	"errors"
	"time"
)

func ToStringKeys(val interface{}) (interface{}, error) {
	var err error
	switch val := val.(type) {
	case time.Time:
		return val.Format("2006-01-02"), nil
	case map[string]interface{}:
		s := make(map[string]interface{})
		for k, v := range val {
			s[k], err = ToStringKeys(v)
			if err != nil {
				return nil, err
			}
		}
		return s, nil
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, v := range val {
			k, ok := k.(string)
			if !ok {
				return nil, errors.New("found non-string key")
			}
			m[k], err = ToStringKeys(v)
			if err != nil {
				return nil, err
			}
		}
		return m, nil
	case []interface{}:
		var l = make([]interface{}, len(val))
		for i, v := range val {
			l[i], err = ToStringKeys(v)
			if err != nil {
				return nil, err
			}
		}
		return l, nil
	default:
		return val, nil
	}
}

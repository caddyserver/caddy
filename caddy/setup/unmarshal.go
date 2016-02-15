package setup

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
)

// Unmarshal attempts to fill a struct with data from the controller. It can fill struct fields of the following tpyes:
//
// Single Fields: string,int,bool,net.IP,net.Addr(CIDR block)
// Slices: []string,[]int,[]net.IP,[]net.Addr   (single values specified multiple times)
// map[string]string
// [][]string   (for anything else that needs manual post processing)
//
// It will attempt to fill fields based on name, or you can override with a `caddy:"name"` struct tag. When inferring name matches, case insensitive matching may be employed.
func (c *Controller) Unmarshal(v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("Unmarshal requires pointer to struct")
	}
	rv = reflect.Indirect(rv)
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("Unmarshal requires pointer to struct")
	}
	c.RemainingArgs()
	//TODO: pack args? Perhaps struct tags to identify
	for c.NextBlock() {
		field := findBestField(&rv, c.Val())
		if field == nil {
			return c.Errf("Unknown field: %s", c.Val())
		}
		args := c.RemainingArgs()
		if err := packField(field, args, c); err != nil {
			return err
		}
	}
	return nil
}

func packField(field *reflect.Value, args []string, c *Controller) error {
	typStr := field.Type().String()
	if typStr == "net.IP" || typStr == "[]net.IP" {
		if len(args) != 1 {
			return c.ArgErr()
		}
		ip := net.ParseIP(args[0])
		if ip == nil {
			return c.Errf("Invalid IP: %s", args[0])
		}
		val := reflect.ValueOf(ip)
		if typStr == "net.IP" {
			field.Set(val)
		} else {
			field.Set(reflect.Append(*field, val))
		}
		return nil
	}
	if typStr == "net.Addr" || typStr == "[]net.Addr" {
		if len(args) != 1 {
			return c.ArgErr()
		}
		_, ad, err := net.ParseCIDR(args[0])
		if err != nil {
			return c.Errf("Invalid CIDR: %s (%s)", args[0], err)
		}
		val := reflect.ValueOf(ad)
		if typStr == "net.Addr" {
			field.Set(val)
		} else {
			field.Set(reflect.Append(*field, val))
		}
		return nil
	}
	if typStr == "map[string]string" {
		if field.IsNil() {
			field.Set(reflect.MakeMap(field.Type()))
		}
		if len(args) != 2 {
			return c.ArgErr()
		}
		k, v := reflect.ValueOf(args[0]), reflect.ValueOf(args[1])
		field.SetMapIndex(k, v)
		return nil
	}
	if typStr == "[][]string" {
		field.Set(reflect.Append(*field, reflect.ValueOf(args)))
		return nil
	}
	switch field.Kind() {
	case reflect.String:
		if len(args) != 1 {
			return c.ArgErr()
		}
		field.SetString(args[0])
	case reflect.Int:
		if len(args) != 1 {
			return c.ArgErr()
		}
		i, err := strconv.Atoi(args[0])
		if err != nil {
			return c.Err(err.Error())
		}
		field.SetInt(int64(i))
	case reflect.Bool:
		if len(args) == 0 {
			field.SetBool(true)
		} else if len(args) != 1 {
			return c.ArgErr()
		} else {
			if args[0] == "true" {
				field.SetBool(true)
			} else if args[0] == "false" {
				field.SetBool(false)
			} else {
				return c.Errf("Invalid bool value: %s", args[0])
			}
		}
	case reflect.Slice:
		elemType := field.Type().Elem()
		switch elemType.Kind() {
		case reflect.String:
			if len(args) != 1 {
				return c.ArgErr()
			}
			field.Set(reflect.Append(*field, reflect.ValueOf(args[0])))
		case reflect.Int:
			if len(args) != 1 {
				return c.ArgErr()
			}
			i, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			field.Set(reflect.Append(*field, reflect.ValueOf(i)))
		default:
			return c.Errf("Can't pack into %s [%s]", field.Type().String(), field.Kind().String())
		}
	default:
		return c.Errf("Can't pack into %s (%s)", field.Type().String(), field.Kind().String())
	}
	return nil
}

func findBestField(rv *reflect.Value, name string) *reflect.Value {
	var poorMatch string
	var nameMatch string
	var exactMatch string
	var field string
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tags := f.Tag.Get("caddy")
		tagParts := strings.Split(tags, ",")
		if tagParts[0] == name {
			field = f.Name
			break
		}
		if f.Name == name {
			exactMatch = f.Name
		} else if strings.ToLower(f.Name) == strings.ToLower(name) {
			nameMatch = f.Name
		} else if strings.ToLower(strings.Replace(f.Name, "_", "", -1)) == strings.ToLower(name) {
			poorMatch = f.Name
		}
	}
	if field == "" {
		field = exactMatch
	}
	if field == "" {
		field = nameMatch
	}
	if field == "" {
		field = poorMatch
	}
	if field == "" {
		return nil
	}
	v := rv.FieldByName(field)
	return &v
}

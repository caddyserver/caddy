package awslambda

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/mholt/caddy"
)

// Configuration for a single awslambda block
type Config struct {
	// Path this config block maps to
	Path string
	// AWS Access Key. If omitted, AWS_ACCESS_KEY_ID env var is used.
	AwsAccess string
	// AWS Secret Key. If omitted, AWS_SECRET_ACCESS_KEY env var is used.
	AwsSecret string
	// AWS Region. If omitted, AWS_REGION env var is used.
	AwsRegion string
	// Optional qualifier to use on Invoke requests.
	// This can be used to pin a configuration to a particular alias (e.g. 'prod' or 'dev')
	Qualifier string
	// Function name include rules. Prefix and suffix '*' globs are supported.
	// Functions matching *any* of these rules will be proxied.
	// If Include is empty, all function names will be allowed (unless explicitly excluded).
	Include []string
	// Function name exclude rules. Prefix and suffix '*" globs are supported.
	// Functions matching *any* of these rules will be excluded, and not proxied.
	// If Exclude is empty, no exclude rules will be applied.
	Exclude []string

	invoker Invoker
}

// AcceptsFunction tests whether the given function name is supported for
// this configuration by applying the Include and Exclude rules.
//
// Some additional lightweight sanity tests are also performed.  For example,
// empty strings and names containing periods (prohibited by AWS Lambda) will
// return false, but there is no attempt to ensure that all AWS Lambda naming
// rules are validated.  That is, some invalid names could be passed through.
//
func (c *Config) AcceptsFunction(name string) bool {
	if name == "" || strings.Index(name, ".") >= 0 {
		return false
	}

	if len(c.Include) > 0 {
		found := false
		for _, k := range c.Include {
			if matchGlob(name, k) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	for _, k := range c.Exclude {
		if matchGlob(name, k) {
			return false
		}
	}

	return true
}

// ToAwsConfig returns a new *aws.Config instance using the AWS related values on Config.
// If AwsRegion is empty, the AWS_REGION env var is used.
// If AwsAccess is empty, the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars are used.
func (c *Config) ToAwsConfig() *aws.Config {
	awsConf := aws.NewConfig()
	if c.AwsRegion != "" {
		awsConf.WithRegion(c.AwsRegion)
	}
	if c.AwsAccess != "" {
		awsConf.WithCredentials(credentials.NewStaticCredentials(
			c.AwsAccess, c.AwsSecret, "",
		))
	}
	return awsConf
}

func (c *Config) initLambdaClient() error {
	sess, err := session.NewSession(c.ToAwsConfig())
	if err != nil {
		return err
	}
	c.invoker = lambda.New(sess)
	return nil
}

// ParseConfig parses a Caddy awslambda config block into a Config struct.
func ParseConfigs(c *caddy.Controller) ([]*Config, error) {
	configs := make([]*Config, 0)

	var conf *Config
	last := ""

	for c.Next() {
		val := c.Val()
		lastTmp := last
		last = ""
		switch lastTmp {
		case "awslambda":
			conf = &Config{
				Path:    val,
				Include: []string{},
				Exclude: []string{},
			}
			configs = append(configs, conf)
		case "aws_access":
			conf.AwsAccess = val
		case "aws_secret":
			conf.AwsSecret = val
		case "aws_region":
			conf.AwsRegion = val
		case "qualifier":
			conf.Qualifier = val
		case "include":
			conf.Include = append(conf.Include, val)
			conf.Include = append(conf.Include, c.RemainingArgs()...)
		case "exclude":
			conf.Exclude = append(conf.Exclude, val)
			conf.Exclude = append(conf.Exclude, c.RemainingArgs()...)
		default:
			last = val
		}
	}

	for _, conf := range configs {
		err := conf.initLambdaClient()
		if err != nil {
			return nil, err
		}
	}

	return configs, nil
}

// matchGlob returns true if string s matches the rule.
// Simple prefix and suffix wildcards are supported with '*'.
// For example, string 'hello' matches rules: 'hello', 'hel*', '*llo', '*ell*'
func matchGlob(s, rule string) bool {
	if s == rule {
		return true
	}

	if strings.HasPrefix(rule, "*") {
		if strings.HasSuffix(rule, "*") {
			rule = rule[1 : len(rule)-1]
			return strings.Index(s, rule) >= 0
		} else {
			return strings.HasSuffix(s, rule[1:])
		}
	} else if strings.HasSuffix(rule, "*") {
		return strings.HasPrefix(s, rule[0:len(rule)-1])
	} else {
		return false
	}
}

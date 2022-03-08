package caddy_test

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

/**
 * @Description:
 * @Date: 2022/3/8 13:58
 */

func TestLogLevel(t *testing.T) {
	logCfg, logFile, err := testLogLevelCfgBytes()
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	//caddytest.NewTester(t)
	if err := caddy.Load(logCfg, false); err != nil { //logCfg.openLogs(ctx); err != nil {
		t.Errorf("open logs error. err: %v", err)
		return
	}

	type logFn func(msg string, fields ...zap.Field)
	time.Now().String()
	prefix := time.Now().String() + " test error level. "
	prefixLevelChangeInfo := prefix + "change log level to info. "
	prefixLevelChangeDebug := prefix + "change log level to debug. "
	testSuits := [][]struct {
		expect bool
		msg    string
		fn     logFn
	}{
		{
			{false, prefix + "none output log, not reason: log level is error, current level debug.", caddy.Log().Debug},
			{false, prefix + "none output log, not reason: log level is error, current level info.", caddy.Log().Info},
			{true, prefix + "content output log,current level error.", caddy.Log().Error},
		},
		{
			{false, prefixLevelChangeInfo + "none output log, not reason: log level is info, current level debug.", caddy.Log().Debug},
			{true, prefixLevelChangeInfo + "none output log, not reason: log level is info, current level info.", caddy.Log().Info},
			{true, prefixLevelChangeInfo + "content output log,current level error.", caddy.Log().Error},
		},
		{
			{true, prefixLevelChangeDebug + "none output log, not reason: log level is debug, current level debug.", caddy.Log().Debug},
			{true, prefixLevelChangeDebug + "none output log, not reason: log level is debug, current level info.", caddy.Log().Info},
			{true, prefixLevelChangeDebug + "content output log,current level error.", caddy.Log().Error},
		},
	}
	levelMap := map[int]zapcore.Level{1: zap.InfoLevel, 2: zapcore.DebugLevel}
	for idx, items := range testSuits {
		if l, ok := levelMap[idx]; ok {
			caddy.SetLogLevel(l)
		}
		for _, item := range items {
			item.fn(item.msg)
		}
	}
	// wait log to error
	<-time.NewTicker(time.Second * 2).C
	logContentBytes, err := ioutil.ReadFile(logFile)
	if err != nil {
		t.Errorf("read log file error. file: %s, err: %s", logFile, err.Error())
		return
	}
	for _, items := range testSuits {
		for _, item := range items {
			actual := true
			if strings.Index(string(logContentBytes), item.msg) == -1 {
				actual = false
			}
			if actual != item.expect {
				t.Errorf("find '%s' in log file error. actual: %v, expect: %v", item.msg, actual, item.expect)
				continue
			}
		}
	}

}

func testLogLevelCfgBytes() ([]byte, string, error) {
	logFile, err := ioutil.TempFile("", "caddy_test_log_level")
	if err != nil {
		return nil, "", fmt.Errorf("get tmp file name error. err: %s", err.Error())
	}
	defer logFile.Close()
	logCfgStr := `{"logging":{
    "logs": {
        "default": {
            "encoder": {
                "format": "json",
                "message_key": "msg",
                "level_key": "level",
                "time_key": "ts",
                "name_key": "logger",
                "caller_key": "caller",
                "stacktrace_key": "stacktrace",
                "line_ending": "\n",
                "time_format": "2006-01-02 15:04:05.000",
                "duration_format": "seconds",
                "level_format": "lower"
            },
            "level": "error",
            "writer": {
                "filename": "` + logFile.Name() + `",
				"output":"file"
            },
            "exclude": [
                "http.log.access"
            ]
        }
    }
}}`
	return []byte(logCfgStr), logFile.Name(), nil
}

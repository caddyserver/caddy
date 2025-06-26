// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import "testing"

func TestCustomLog_loggerAllowed(t *testing.T) {
	type fields struct {
		BaseLog BaseLog
		Include []string
		Exclude []string
	}
	type args struct {
		name     string
		isModule bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "include",
			fields: fields{
				Include: []string{"foo"},
			},
			args: args{
				name:     "foo",
				isModule: true,
			},
			want: true,
		},
		{
			name: "exclude",
			fields: fields{
				Exclude: []string{"foo"},
			},
			args: args{
				name:     "foo",
				isModule: true,
			},
			want: false,
		},
		{
			name: "include and exclude",
			fields: fields{
				Include: []string{"foo"},
				Exclude: []string{"foo"},
			},
			args: args{
				name:     "foo",
				isModule: true,
			},
			want: false,
		},
		{
			name: "include and exclude (longer namespace)",
			fields: fields{
				Include: []string{"foo.bar"},
				Exclude: []string{"foo"},
			},
			args: args{
				name:     "foo.bar",
				isModule: true,
			},
			want: true,
		},
		{
			name: "excluded module is not printed",
			fields: fields{
				Include: []string{"admin.api.load"},
				Exclude: []string{"admin.api"},
			},
			args: args{
				name:     "admin.api",
				isModule: false,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := &CustomLog{
				BaseLog: tt.fields.BaseLog,
				Include: tt.fields.Include,
				Exclude: tt.fields.Exclude,
			}
			if got := cl.loggerAllowed(tt.args.name, tt.args.isModule); got != tt.want {
				t.Errorf("CustomLog.loggerAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

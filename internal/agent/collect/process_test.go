package collect

import "testing"

// Guards the ТЗ §5.6 false-positive requirement: a shell that merely mentions
// an N8N_* env var or a path containing "n8n" must NOT be classified as an
// n8n process; a real n8n invocation must.
func TestClassifyProcessAvoidsFalsePositives(t *testing.T) {
	cases := []struct {
		cmdline string
		want    string
	}{
		{"/bin/bash -c export N8N_ENCRYPTION_KEY=xyz && do_stuff", ""},
		{"node /opt/app/dist/index.js", ""},
		{"/usr/local/bin/n8n start", "n8n"},
		{"node /usr/lib/node_modules/n8n/bin/n8n", "n8n"},
		{"n8n worker", "n8n"},
		{"python3 -m celery -A app worker", "python-runner"},
		{"python3 manage.py runserver", ""},
		{"node-red", "node-automation"},
	}
	for _, c := range cases {
		if got := classifyProcess(c.cmdline); got != c.want {
			t.Errorf("classifyProcess(%q)=%q want %q", c.cmdline, got, c.want)
		}
	}
}

package wordlist

import "strings"

const builtinWordlist = `admin
login
dashboard
api
api/v1
api/v2
config
backup
test
debug
uploads
static
media
assets
css
js
images
robots.txt
sitemap.xml
.env
.git/HEAD
.git/config
.htaccess
wp-admin
wp-login.php
wp-config.php
phpmyadmin
swagger
swagger.json
openapi.json
docs
health
healthz
metrics
status
console
shell
server-status
server-info
actuator
actuator/env
actuator/health
graphql
graphiql
user
users
account
register
signup
logout
profile
settings
panel
manager
management
portal
internal
private
secure
secret
hidden
old
bak
tmp
temp
cache
log
logs
error
errors
trace
web.config
app.config
appsettings.json
package.json
yarn.lock
Dockerfile
docker-compose.yml
`

// Builtin returns the embedded wordlist as lines.
func Builtin() []string {
	var lines []string
	for _, l := range strings.Split(builtinWordlist, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines
}

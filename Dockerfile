FROM sharelatex/sharelatex:2.0.1
LABEL maintainer="github.com/worksasintended"
RUN npm install ldapjs
#overwrite  AuthenticationManager.js
COPY AuthenticationManager.js /var/www/sharelatex/web/app/src/Features/Authentication/


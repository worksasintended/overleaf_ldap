FROM sharelatex/sharelatex:2cdbdc229d4f
LABEL maintainer="github.com/worksasintended"
RUN npm install ldapjs
#overwrite  AuthenticationManager.js
COPY AuthenticationManager.js /var/www/sharelatex/web/app/src/Features/Authentication/


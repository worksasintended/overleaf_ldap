# overleaf_ldap
ldap implementation for the overleaf community edition [overleaf](https://github.com/overleaf/overleaf)

Work by [kemnitzs](https://github.com/kemnitzs) and [worksasintended](https://github.com/worksasintended)
This solution uses ldapjs.

## Usage

Edit `docker-compose.yml` to fit your local setup. 

- `ADMIN_MAIL`: login for local admin user which gets checked before the ldap routine during login. This is the only user that can login if ldap is down and does not need to exist in ldap. You need to create the same user in overleaf, for example using the launchpad. The admin user does not have to be in the same domainas other users. 
- `DOMAIN`: At the current state, only users of a single domain are allowed (though easy to change). For a given user `user123@domain123.com` trying to login, `domain123.com` is compared with `DOMAIN`. For the ldap authentification only the username `user123` is used.  
- `LDAP_SERVER`: address of the ldap server
- `LDAP_BIND_DN`: bind dn which allows to search users inside ldap
- `LDAP_BIND_PW`: secret corresponding to `LDAP_BIND_DN`

For persistent storage use volumes. For secure connections either use nginx-proxy or add the certificate to nginx inside the worksasintended/overleaf-ldap container and adjust nginx settings accordingly.

### Start the server using docker-compose

``` 
docker-compose up -d

```


## Building the image

The image `worksasintended/overleaf-ldap` is available at [dockerhub](https://cloud.docker.com/u/worksasintended/repository/docker/worksasintended/overleaf_ldap)

You can also build it yourself simply using the `docker build` command or the `build` script. 



const Settings = require('settings-sharelatex')
const {User} = require('../../models/User')
const {db, ObjectId} = require('../../infrastructure/mongojs')
const bcrypt = require('bcrypt')
const EmailHelper = require('../Helpers/EmailHelper')
const V1Handler = require('../V1/V1Handler')
const {
    InvalidEmailError,
    InvalidPasswordError
} = require('./AuthenticationErrors')
const util = require('util')
const ldap = require('ldapjs')

const BCRYPT_ROUNDS = Settings.security.bcryptRounds || 12
const BCRYPT_MINOR_VERSION = Settings.security.bcryptMinorVersion || 'a'

const _checkWriteResult = function (result, callback) {
    // for MongoDB
    if (result && result.nModified === 1) {
        callback(null, true)
    } else {
        callback(null, false)
    }
}

const AuthenticationManager = {
    authenticate(query, password, callback) {
        // Using Mongoose for legacy reasons here. The returned User instance
        // gets serialized into the session and there may be subtle differences
        // between the user returned by Mongoose vs mongojs (such as default values)
        User.findOne(query, (error, user) => {
            AuthenticationManager.authUserObj(error, user, query, password, callback)
        })
    },
    //login with any passwd
    login(user, password, callback) {
        AuthenticationManager.checkRounds(
            user,
            user.hashedPassword,
            password,
            function (err) {
                if (err) {
                    return callback(err)
                }
                callback(null, user)
            }
        )
    },

    createIfNotExistAndLogin(query, adminMail, user, callback) {
        if (query.email != adminMail & (!user || !user.hashedPassword)) {
            //create random pass for local userdb, does not get checked for ldap users during login
            let pass = require("crypto").randomBytes(32).toString("hex")
            const userRegHand = require('../User/UserRegistrationHandler.js')
            userRegHand.registerNewUser({
                    email: query.email,
                    password: pass
                },
                function (error, user) {
                    if (error) {
                        callback(error)
                    }
                    user.admin = false
		    user.emails[0].confirmedAt = Date.now()
	            user.save()
                    console.log("user %s added to local library", query.email)
                    User.findOne(query, (error, user) => {
                            if (error) {
                                return callback(error)
                            }
                            if (user && user.hashedPassword) {
                                AuthenticationManager.login(user, "randomPass", callback)
                            }
                        }
                    )


                })
            //return callback(null, null)
        } else {
            AuthenticationManager.login(user, "randomPass", callback)
        }
    },

    authUserObj(error, user, query, password, callback) {
        //non ldap / local admin user
        const adminMail = process.env.ADMIN_MAIL
        const domain = process.env.DOMAIN
        if (error) {
            return callback(error)
        }
        //check for domain
        //console.log("check for domain")
        if (query.email != adminMail && query.email.split('@')[1] != domain) {
            //console.log("wrong domain")
            //console.log(query.email.split('@')[1])
            return callback(null, null)
        }
        //check for local admin user
        if (user && user.hashedPassword) {
            //console.log("existing user: login event")
            if (user.email == adminMail) {
                //console.log("admin user: login event")
                bcrypt.compare(password, user.hashedPassword, function (error, match) {
                    if (error) {
                        return callback(error)
                    }
                    if (!match) {
                        //console.log("admin pass does not match")
                        return callback(null, null)
                    }
                    //console.log("admin user logged in")
                    AuthenticationManager.login(user, password, callback)
                })
                return null
            }
        }
        //check if user is in ldap
        AuthenticationManager.ldapAuth(query, password, AuthenticationManager.createIfNotExistAndLogin, callback, adminMail, user)
    },

    validateEmail(email) {
        const parsed = EmailHelper.parseEmail(email)
        if (!parsed) {
            return new InvalidEmailError({message: 'email not valid'})
        }
        return null
    },

    // validates a password based on a similar set of rules to `complexPassword.js` on the frontend
    // note that `passfield.js` enforces more rules than this, but these are the most commonly set.
    // returns null on success, or an error string.
    validatePassword(password) {
        if (password == null) {
            return new InvalidPasswordError({
                message: 'password not set',
                info: {code: 'not_set'}
            })
        }

        let allowAnyChars, min, max
        if (Settings.passwordStrengthOptions) {
            allowAnyChars = Settings.passwordStrengthOptions.allowAnyChars === true
            if (Settings.passwordStrengthOptions.length) {
                min = Settings.passwordStrengthOptions.length.min
                max = Settings.passwordStrengthOptions.length.max
            }
        }
        allowAnyChars = !!allowAnyChars
        min = min || 6
        max = max || 72

        // we don't support passwords > 72 characters in length, because bcrypt truncates them
        if (max > 72) {
            max = 72
        }

        if (password.length < min) {
            return new InvalidPasswordError({
                message: 'password is too short',
                info: {code: 'too_short'}
            })
        }
        if (password.length > max) {
            return new InvalidPasswordError({
                message: 'password is too long',
                info: {code: 'too_long'}
            })
        }
        if (
            !allowAnyChars &&
            !AuthenticationManager._passwordCharactersAreValid(password)
        ) {
            return new InvalidPasswordError({
                message: 'password contains an invalid character',
                info: {code: 'invalid_character'}
            })
        }
        return null
    },

    setUserPassword(userId, password, callback) {
        AuthenticationManager.setUserPasswordInV2(userId, password, callback)
    },

    checkRounds(user, hashedPassword, password, callback) {
        // Temporarily disable this function, TODO: re-enable this
        if (Settings.security.disableBcryptRoundsUpgrades) {
            return callback()
        }
        // check current number of rounds and rehash if necessary
        const currentRounds = bcrypt.getRounds(hashedPassword)
        if (currentRounds < BCRYPT_ROUNDS) {
            AuthenticationManager.setUserPassword(user._id, password, callback)
        } else {
            callback()
        }
    },

    hashPassword(password, callback) {
        bcrypt.genSalt(BCRYPT_ROUNDS, BCRYPT_MINOR_VERSION, function (error, salt) {
            if (error) {
                return callback(error)
            }
            bcrypt.hash(password, salt, callback)
        })
    },

    setUserPasswordInV2(userId, password, callback) {
        const validationError = this.validatePassword(password)
        if (validationError) {
            return callback(validationError)
        }
        this.hashPassword(password, function (error, hash) {
            if (error) {
                return callback(error)
            }
            db.users.update(
                {
                    _id: ObjectId(userId.toString())
                },
                {
                    $set: {
                        hashedPassword: hash
                    },
                    $unset: {
                        password: true
                    }
                },
                function (updateError, result) {
                    if (updateError) {
                        return callback(updateError)
                    }
                    _checkWriteResult(result, callback)
                }
            )
        })
    },

    setUserPasswordInV1(v1UserId, password, callback) {
        const validationError = this.validatePassword(password)
        if (validationError) {
            return callback(validationError.message)
        }

        V1Handler.doPasswordReset(v1UserId, password, function (error, reset) {
            if (error) {
                return callback(error)
            }
            callback(error, reset)
        })
    },

    _passwordCharactersAreValid(password) {
        let digits, letters, lettersUp, symbols
        if (
            Settings.passwordStrengthOptions &&
            Settings.passwordStrengthOptions.chars
        ) {
            digits = Settings.passwordStrengthOptions.chars.digits
            letters = Settings.passwordStrengthOptions.chars.letters
            lettersUp = Settings.passwordStrengthOptions.chars.letters_up
            symbols = Settings.passwordStrengthOptions.chars.symbols
        }
        digits = digits || '1234567890'
        letters = letters || 'abcdefghijklmnopqrstuvwxyz'
        lettersUp = lettersUp || 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        symbols = symbols || '@#$%^&*()-_=+[]{};:<>/?!£€.,'

        for (let charIndex = 0; charIndex <= password.length - 1; charIndex++) {
            if (
                digits.indexOf(password[charIndex]) === -1 &&
                letters.indexOf(password[charIndex]) === -1 &&
                lettersUp.indexOf(password[charIndex]) === -1 &&
                symbols.indexOf(password[charIndex]) === -1
            ) {
                return false
            }
        }
        return true
    },

    ldapAuth(query, passwd, onSuccess, callback, adminMail, userObj) {
        const client = ldap.createClient({
            url: process.env.LDAP_SERVER
        });
        const bindDn = process.env.LDAP_BIND_DN
        const bindPassword = process.env.LDAP_BIND_PW
        client.bind(bindDn, bindPassword, function (err) {
            if (err == null) {
                const opts = {
                    filter: '(&(objectClass=posixAccount)(uid=' + query.email.split('@')[0] + '))',
                    scope: 'sub',
                    attributes: ['dn']
                };

                client.search('ou=Personen,dc=uni-greifswald,dc=de,dc=TLD', opts, function (err, res) {
                    if (err) {
                        return callback(null, null)
                    }
                    res.on('searchEntry', function (entry) {
                        userDn = entry.objectName
                        client.bind(userDn, passwd, function (err) {
                            if (err == null) {
                                //console.log("ldap positive")
                                onSuccess(query, adminMail, userObj, callback)
                                client.unbind()
                                return null
                            } else {
                                //console.log("ldap negative")
                                client.unbind()
                                return callback(null, null)
                            }
                        })
                    })
                    res.on('error', err => {
                        console.error('error: ' + err.message);
                        client.unbind()
                        return callback(null, null)
                    });
                    res.on('end', result => {
                        //if nothing written (user not found)
                        if(result.connection._writableState.writing == false){
                            client.unbind()
                            return callback(null, null)
                        }
                    });
                });

            } else {
                return callback(null, null)
            }
        })
    }
}

AuthenticationManager.promises = {
    authenticate: util.promisify(AuthenticationManager.authenticate),
    hashPassword: util.promisify(AuthenticationManager.hashPassword)
}

module.exports = AuthenticationManager

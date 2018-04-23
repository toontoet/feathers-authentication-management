
/* eslint-env node */

const errors = require('@feathersjs/errors');
const debug = require('debug')('authManagement:verifyInviteSetPwd');

const {
  getUserData,
  ensureObjPropsValid,
  ensureValuesAreStrings,
  hashPassword,
  notifier
} = require('./helpers');

module.exports.verifyInviteWithLongToken = function (options, verifyToken, password) {
  return Promise.resolve()
    .then(() => {
      ensureValuesAreStrings(verifyToken, password);

      return verifyInviteSetPwd(options, { verifyToken }, { verifyToken }, password);
    });
};

module.exports.verifyInviteWithShortToken = function (options, verifyShortToken, identifyUser,password) {
  return Promise.resolve()
    .then(() => {
      ensureValuesAreStrings(verifyShortToken, password);
      ensureObjPropsValid(identifyUser, options.identifyUserProps);

      return verifySignup(options, identifyUser, { verifyShortToken }, password);
    });
};

function verifyInviteSetPwd (options, query, tokens , password) {
  debug('verifyInviteSetPwd', query, tokens);
  const users = options.app.service(options.service);
  const usersIdName = users.id;
  const {
    sanitizeUserForClient
  } = options;



  return Promise.all([
    users.find({ query }),
    hashPassword(options.app, password)
  ])
    .then(([data,hashPassword]) => {
        return [getUserData(data, ['isNotVerifiedOrHasVerifyChanges', 'verifyNotExpired']), hashPassword];
    })
    .then(([user, hashPassword]) => {
      if (!Object.keys(tokens).every(key => tokens[key] === user[key])) {
        return eraseVerifyProps(user, user.isVerified)
          .then(() => {
            throw new errors.BadRequest('Invalid token. Get for a new one. (authManagement)',
              { errors: { $className: 'badParam' } });
          });
      }

      return eraseVerifyProps(user, user.verifyExpires > Date.now(), user.verifyChanges || {}, hashPassword)
        .then(user1 => notifier(options.notifier, 'verifySignup', user1))
        .then(user1 => sanitizeUserForClient(user1));
    });

  function eraseVerifyProps (user, isVerified, verifyChanges, hashPassword) {
    const patchToUser = Object.assign({}, verifyChanges || {},
    { password: hashPassword },
    {
      isVerified,
      verifyToken: null,
      verifyShortToken: null,
      verifyExpires: null,
      verifyChanges: {}
    });

    return patchUser(user, patchToUser);
  }

  function patchUser (user, patchToUser) {
    return users.patch(user[usersIdName], patchToUser, {}) // needs users from closure
      .then(() => Object.assign(user, patchToUser));
  }
}

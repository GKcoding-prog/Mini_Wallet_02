const { models } = require('../models');

async function checkEmailExists(email) {
  const existingUser = await models.User.findOne({ where: { email } });
  return !!existingUser;
}

module.exports = { checkEmailExists };
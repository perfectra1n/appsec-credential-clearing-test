/*
 * Copyright (c) 2014-2020 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const config = require('config')
const colors = require('colors/safe')
const logger = require('../logger')

const validateChatBot = (trainingData, exitOnFailure = true) => {
  let success = true
  success = checkIntentWithHandlerExists(trainingData, 'queries.couponCode', 'couponCode') && success
  success = checkIntentWithHandlerExists(trainingData, 'queries.productPrice', 'productPrice') && success
  success = checkIntentWithHandlerExists(trainingData, 'queries.functionTest', 'testFunction') && success
  if (success) {
    logger.info(`Chatbot training data ${colors.bold(config.get('application.chatBot.trainingData'))} validated (${colors.green('OK')})`)
  } else {
    logger.warn(`Chatbot training data ${colors.bold(config.get('application.chatBot.trainingData'))} validated (${colors.red('NOT OK')})`)
    logger.warn(`Visit ${colors.yellow('https://pwning.owasp-juice.shop/appendix/chatbot.html')} for the training data schema definition.`)
    if (exitOnFailure) {
      logger.error(colors.red('Exiting due to configuration errors!'))
      process.exit(1)
    }
  }
  return success
}

const checkIntentWithHandlerExists = (trainingData, intent, handler) => {
  let success = true
  const intentData = trainingData.data.filter(data => data.intent === intent)
  if (intentData.length === 0) {
    logger.warn(`Intent ${colors.italic(intent)} is missing in chatbot training data (${colors.red('NOT OK')})`)
    success = false
  } else {
    if (intentData[0].answers.filter(answer => answer.action === 'function' && answer.handler === handler).length === 0) {
      logger.warn(`Answer with ${colors.italic('function')} action and handler ${colors.italic(handler)} is missing for intent ${colors.italic(intent)} (${colors.red('NOT OK')})`)
      success = false
    }
  }
  return success
}

validateChatBot.checkIntentWithHandlerExists = checkIntentWithHandlerExists

module.exports = validateChatBot

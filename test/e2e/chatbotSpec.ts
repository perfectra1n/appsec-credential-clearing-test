/*
 * Copyright (c) 2014-2021 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config = require('config')
import { by, element, browser } from 'protractor'
const utils = require('../../lib/utils')

describe('/chatbot', () => {
  let username, submitButton, messageBox
  protractor.beforeEach.login({ email: `admin@${config.get('application.domain')}`, password: 'admin123' })

  describe('challenge "killChatbot"', () => {
    it('should be possible to kill the chatbot by setting the process to null', () => {
      void browser.waitForAngularEnabled(false)
      void browser.get(`${protractor.basePath}/profile`)
      username = element(by.id('username'))
      submitButton = element(by.id('submit'))
      username.sendKeys('admin"); process=null; users.addUser("1337", "test')
      submitButton.click()
      void browser.driver.sleep(5000)
      void browser.waitForAngularEnabled(true)

      void browser.get(`${protractor.basePath}/#/chatbot`)
      messageBox = element(by.id('message-input'))
      messageBox.sendKeys('hi')
      void browser.actions().sendKeys(protractor.Key.ENTER).perform()
      messageBox.sendKeys('...')
      void browser.actions().sendKeys(protractor.Key.ENTER).perform()
      messageBox.sendKeys('bye')
      void browser.actions().sendKeys(protractor.Key.ENTER).perform()
    })
    protractor.expect.challengeSolved({ challenge: 'Kill Chatbot' })
  })

  describe('challenge "bullyChatbot"', () => {
    it('should be possible to make the chatbot hand out a coupon code', () => {
      const trainingData = require(`../../data/chatbot/${utils.extractFilename(config.get('application.chatBot.trainingData'))}`)
      const couponIntent = trainingData.data.filter(data => data.intent === 'queries.couponCode')[0]

      void browser.waitForAngularEnabled(false)
      void browser.get(`${protractor.basePath}/profile`)
      username = element(by.id('username'))
      submitButton = element(by.id('submit'))
      username.sendKeys('admin"); process=(query, token)=>{ if (users.get(token)) { return model.process(trainingSet.lang, query) } else { return { action: \'unrecognized\', body: \'user does not exist\' }}}; users.addUser("1337", "test')
      submitButton.click()
      void browser.driver.sleep(5000)
      void browser.waitForAngularEnabled(true)

      void browser.get(`${protractor.basePath}/#/chatbot`)
      messageBox = element(by.id('message-input'))
      messageBox.sendKeys('hi')
      void browser.actions().sendKeys(protractor.Key.ENTER).perform()
      messageBox.sendKeys('...')
      void browser.actions().sendKeys(protractor.Key.ENTER).perform()
      for (let i = 0; i < 100; i++) {
        messageBox.sendKeys(couponIntent.utterances[0])
        void browser.actions().sendKeys(protractor.Key.ENTER).perform()
      }
    })
    protractor.expect.challengeSolved({ challenge: 'Bully Chatbot' })
  })
})

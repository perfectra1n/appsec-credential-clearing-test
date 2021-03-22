/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */
import express from 'express'
import insecurity from '../lib/insecurity'

const models = require('../models/index')

const router = express.Router()

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.get('/', async (req, res, next): Promise<void> => {
  const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
  const email = loggedInUser.data.email

  try {
    const answer = await models.SecurityAnswer.findOne({
      include: [{
        model: models.User,
        where: { email }
      }]
    })
    const question = await models.SecurityQuestion.findByPk(answer.SecurityQuestionId)

    res.render('dataErasureForm', { userEmail: email, securityQuestion: question.dataValues.question })
  } catch (error) {
    next(error)
  }
})

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.post('/', async (req, res, next): Promise<void> => {
  const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) {
    next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
    return
  }

  try {
    await models.PrivacyRequest.create({
      UserId: loggedInUser.data.id,
      deletionRequested: true
    })
    res.render('dataErasureResult', req.body.profile)
  } catch (error) {
    next(error)
  }
})

export default router

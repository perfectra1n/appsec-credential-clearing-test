/* jslint node: true */
const models = require('../models/index')
const datacache = require('./datacache')
const config = require('config')
const utils = require('../lib/utils')
const mongodb = require('./mongodb')

const fs = require('fs')
const path = require('path')
const util = require('util')

const readFile = util.promisify(fs.readFile)

function loadStaticData (file) {
  const filePath = path.resolve('./data/data/' + file + '.json')
  return readFile(filePath, 'utf8')
    .then(JSON.parse)
    .catch(() => console.error('Could not open file: "' + filePath + '"'))
}

async function createChallenges () {
  const showHints = config.get('application.showChallengeHints')

  const challenges = await loadStaticData('challenges')

  await Promise.all(
    challenges.map(async ({ name, category, description, difficulty, hint, hintUrl, key }) => {
      try {
        const challenge = await models.Challenge.create({
          name,
          category,
          description,
          difficulty,
          solved: false,
          hint: showHints ? hint : null,
          hintUrl: showHints ? hintUrl : null
        })
        datacache.challenges[key] = challenge
      } catch (err) {
        console.error(`Could not insert Challenge ${name}`)
        console.error(err)
      }
    })
  )
}

async function createUsers () {
  const users = await loadStaticData('users')

  await Promise.all(
    users.map(async ({ email, password, customDomain, key }) => {
      try {
        const completeEmail = customDomain ? email : `${email}@${config.get('application.domain')}`
        const user = await models.User.create({
          email: completeEmail,
          password
        })
        if (key) datacache.users[key] = user
      } catch (err) {
        console.error(`Could not insert User ${name}`)
        console.error(err)
      }
    })
  )
}

function createRandomFakeUsers () {
  function getGeneratedRandomFakeUserEmail () {
    const randomDomain = makeRandomString(4).toLowerCase() + '.' + makeRandomString(2).toLowerCase()
    return makeRandomString(5).toLowerCase() + '@' + randomDomain
  }

  function makeRandomString (length) {
    let text = ''
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

    for (let i = 0; i < length; i++) { text += possible.charAt(Math.floor(Math.random() * possible.length)) }

    return text
  }

  return Promise.all(new Array(config.get('application.numberOfRandomFakeUsers')).fill(0).map(
    () => models.User.create({
      email: getGeneratedRandomFakeUserEmail(),
      password: makeRandomString(5)
    }).then(({ email }) => console.log(`Created random user ${email}`))
  ))
}

function createProducts () {
  const products = config.get('products').map((product) => {
    // set default price values
    product.price = product.price || Math.floor(Math.random())
    product.description = product.description || 'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.'

    // set default image values
    product.image = product.image || 'undefined.png'
    if (utils.startsWith(product.image, 'http')) {
      const imageUrl = product.image
      product.image = decodeURIComponent(product.image.substring(product.image.lastIndexOf('/') + 1))
      utils.downloadToFile(imageUrl, 'app/public/images/products/' + product.image)
    }

    // set deleted at values if configured
    if (product.deletedDate) {
      product.deletedAt = product.deletedDate
      delete product.deletedDate
    }

    return product
  })

  // add Challenge specific information
  const chrismasChallengeProduct = products.find(({ useForChristmasSpecialChallenge }) => useForChristmasSpecialChallenge)
  const tamperingChallengeProduct = products.find(({ urlForProductTamperingChallenge }) => urlForProductTamperingChallenge)
  const blueprintRetrivalChallengeProduct = products.find(({ fileForRetrieveBlueprintChallenge }) => fileForRetrieveBlueprintChallenge)

  chrismasChallengeProduct.description += ' (Seasonal special offer! Limited availability!)'
  chrismasChallengeProduct.deletedAt = '2014-12-27 00:00:00.000 +00:00'
  tamperingChallengeProduct.description += ' <a href="' + tamperingChallengeProduct.urlForProductTamperingChallenge + '" target="_blank">More...</a>'
  tamperingChallengeProduct.deletedAt = null

  let blueprint = blueprintRetrivalChallengeProduct.fileForRetrieveBlueprintChallenge
  if (utils.startsWith(blueprint, 'http')) {
    const blueprintUrl = blueprint
    blueprint = decodeURIComponent(blueprint.substring(blueprint.lastIndexOf('/') + 1))
    utils.downloadToFile(blueprintUrl, 'app/public/images/products/' + blueprint)
  }
  datacache.retrieveBlueprintChallengeFile = blueprint

  return Promise.all(
    products.map(
      ({ reviews = [], useForChristmasSpecialChallenge = false, urlForProductTamperingChallenge = false, ...product }) =>
        models.Product.create(product).catch(
          (err) => {
            console.error(`Could not insert Product ${product.name}`)
            console.error(err)
          }
        ).then((persistedProduct) => {
          if (useForChristmasSpecialChallenge) { datacache.products.christmasSpecial = persistedProduct }
          if (urlForProductTamperingChallenge) { datacache.products.osaft = persistedProduct }
          return persistedProduct
        })
          .then(({ id }) =>
            Promise.all(
              reviews.map(({ text, author }) =>
                mongodb.reviews.insert({
                  message: text,
                  author: `${author}@${config.get('application.domain')}`,
                  product: id
                }).catch((err) => {
                  console.error(`Could not insert Product Review ${text}`)
                  console.error(err)
                })
              )
            )
          )
    )
  )
}

// TODO Config Validation
// Challenge Product can only have one challenge
// Challenges can only be related to one product

module.exports = async () => {
  const creators = [
    createUsers,
    createChallenges,
    createRandomFakeUsers,
    createProducts,
    createBaskets
  ]

  for (const creator of creators) {
    await creator()
  }

  createFeedback()
  createComplaints()
  createRecycles()
  createSecurityQuestions()
  createSecurityAnswers()
}

function createBaskets () {
  const baskets = [
    { UserId: 1 },
    { UserId: 2 },
    { UserId: 3 }
  ]

  const basketItems = [
    {
      BasketId: 1,
      ProductId: 1,
      quantity: 2
    },
    {
      BasketId: 1,
      ProductId: 2,
      quantity: 3
    },
    {
      BasketId: 1,
      ProductId: 3,
      quantity: 1
    },
    {
      BasketId: 2,
      ProductId: 4,
      quantity: 2
    },
    {
      BasketId: 3,
      ProductId: 5,
      quantity: 1
    }
  ]

  return Promise.all([
    ...baskets.map(basket => {
      models.Basket.create(basket).catch((err) => {
        console.error(`Could not insert Basket for UserId ${basket.UserId}`)
        console.error(err)
      })
    }),
    ...basketItems.map(basketItem => {
      models.BasketItem.create(basketItem).catch((err) => {
        console.error(`Could not insert BasketItem for BasketId ${basketItem.BasketId}`)
        console.error(err)
      })
    })
  ])
}

function createFeedback () {
  models.Feedback.create({
    UserId: 1,
    comment: 'I love this shop! Best products in town! Highly recommended!',
    rating: 5
  })
  models.Feedback.create({
    UserId: 2,
    comment: 'Great shop! Awesome service!',
    rating: 4
  })
  models.Feedback.create({
    comment: 'Incompetent customer support! Can\'t even upload photo of broken purchase!<br><em>Support Team: Sorry, only order confirmation PDFs can be attached to complaints!</em>',
    rating: 2
  })
  models.Feedback.create({
    comment: 'This is <b>the</b> store for awesome stuff of all kinds!',
    rating: 4
  })
  models.Feedback.create({
    comment: 'Never gonna buy anywhere else from now on! Thanks for the great service!',
    rating: 4
  })
  models.Feedback.create({
    comment: 'Keep up the good work!',
    rating: 3
  })
  models.Feedback.create({
    UserId: 3,
    comment: 'Nothing useful available here!',
    rating: 1
  })
}

function createComplaints () {
  models.Complaint.create({
    UserId: 3,
    message: 'I\'ll build my own eCommerce business! With Black Jack! And Hookers!'
  })
}

function createRecycles () {
  models.Recycle.create({
    UserId: 2,
    quantity: 800,
    address: 'Starfleet HQ, 24-593 Federation Drive, San Francisco, CA',
    date: '2270-01-17',
    isPickup: true
  })
}

function createSecurityQuestions () {
  models.SecurityQuestion.create({
    question: 'Your eldest siblings middle name?'
  })
  models.SecurityQuestion.create({
    question: 'Mother\'s maiden name?'
  })
  models.SecurityQuestion.create({
    question: 'Mother\'s birth date? (MM/DD/YY)'
  })
  models.SecurityQuestion.create({
    question: 'Father\'s birth date? (MM/DD/YY)'
  })
  models.SecurityQuestion.create({
    question: 'Maternal grandmother\'s first name?'
  })
  models.SecurityQuestion.create({
    question: 'Paternal grandmother\'s first name?'
  })
  models.SecurityQuestion.create({
    question: 'Name of your favorite pet?'
  })
  models.SecurityQuestion.create({
    question: 'Last name of dentist when you were a teenager? (Do not include \'Dr.\')'
  })
  models.SecurityQuestion.create({
    question: 'Your ZIP/postal code when you were a teenager?'
  })
  models.SecurityQuestion.create({
    question: 'Company you first work for as an adult?'
  })
}

function createSecurityAnswers () {
  models.SecurityAnswer.create({
    SecurityQuestionId: 2,
    UserId: 1,
    answer: '@xI98PxDO+06!'
  }).catch(console.error)
  models.SecurityAnswer.create({
    SecurityQuestionId: 1,
    UserId: 2,
    answer: 'Samuel' // https://en.wikipedia.org/wiki/James_T._Kirk
  })
  models.SecurityAnswer.create({
    SecurityQuestionId: 10,
    UserId: 3,
    answer: 'Stop\'n\'Drop' // http://futurama.wikia.com/wiki/Suicide_booth
  })
  models.SecurityAnswer.create({
    SecurityQuestionId: 9,
    UserId: 4,
    answer: 'West-2082' // http://www.alte-postleitzahlen.de/uetersen
  })
  models.SecurityAnswer.create({
    SecurityQuestionId: 7,
    UserId: 5,
    answer: 'Brd?j8sEMziOvvBf§Be?jFZ77H?hgm'
  })
  models.SecurityAnswer.create({
    SecurityQuestionId: 10,
    UserId: 6,
    answer: 'SC OLEA SRL' // http://www.olea.com.ro/
  })
  models.SecurityAnswer.create({
    SecurityQuestionId: 1,
    UserId: 7,
    answer: 'JeRRy' // bruteforcible/
  })
}

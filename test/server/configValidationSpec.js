const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

const validateConfig = require('../../lib/startup/validateConfig')
const { checkThatThereIsOnlyOneProductPerSpecial, checkThatProductArentUsedAsMultipleSpecialProducts, checkSchema } = require('../../lib/startup/validateConfig')

describe('configValidation', () => {
  describe('checkThatThereIsOnlyOneProductPerSpecial', () => {
    it('should accept a valid config', () => {
      const products = [
        {
          name: 'Apple Juice',
          useForChristmasSpecialChallenge: true
        },
        {
          name: 'Orange Juice',
          urlForProductTamperingChallenge: 'foobar'
        },
        {
          name: 'Melon Juice',
          fileForRetrieveBlueprintChallenge: 'foobar'
        },
        {
          name: 'Rippertuer Special Juice',
          keywordsForPastebinDataLeakChallenge: ['bla', 'blubb']
        }
      ]

      expect(checkThatThereIsOnlyOneProductPerSpecial(products)).to.equal(true)
    })

    it('should fail if a multiple products are configured for the same challenge', () => {
      const products = [
        {
          name: 'Apple Juice',
          useForChristmasSpecialChallenge: true
        },
        {
          name: 'Melon Bike',
          useForChristmasSpecialChallenge: true
        },
        {
          name: 'Orange Juice',
          urlForProductTamperingChallenge: 'foobar'
        },
        {
          name: 'Melon Juice',
          fileForRetrieveBlueprintChallenge: 'foobar'
        }
      ]

      expect(checkThatThereIsOnlyOneProductPerSpecial(products)).to.equal(false)
    })

    it('should fail if a required challenge product is missing', () => {
      const products = [
        {
          name: 'Apple Juice',
          useForChristmasSpecialChallenge: true
        },
        {
          name: 'Orange Juice',
          urlForProductTamperingChallenge: 'foobar'
        }
      ]

      expect(checkThatThereIsOnlyOneProductPerSpecial(products)).to.equal(false)
    })
  })

  describe('checkThatThereIsOnlyOneProductPerSpecial', () => {
    it('should accept a valid config', () => {
      const products = [
        {
          name: 'Apple Juice',
          useForChristmasSpecialChallenge: true
        },
        {
          name: 'Orange Juice',
          urlForProductTamperingChallenge: 'foobar'
        },
        {
          name: 'Melon Juice',
          fileForRetrieveBlueprintChallenge: 'foobar'
        },
        {
          name: 'Rippertuer Special Juice',
          keywordsForPastebinDataLeakChallenge: ['bla', 'blubb']
        }
      ]

      expect(checkThatProductArentUsedAsMultipleSpecialProducts(products)).to.equal(true)
    })

    it('should fail if a product is configured for multiple challenges', () => {
      const products = [
        {
          name: 'Apple Juice',
          useForChristmasSpecialChallenge: true,
          urlForProductTamperingChallenge: 'foobar'
        }
      ]

      expect(checkThatProductArentUsedAsMultipleSpecialProducts(products)).to.equal(false)
    })
  })

  it('should accept the default config', () => {
    expect(validateConfig({ exitOnFailure: false })).to.equal(true)
  })

  it('should fail if the config is invalid', () => {
    expect(validateConfig({ products: [], exitOnFailure: false })).to.equal(false)
  })

  it('should accept a config with valid schema', () => {
    const config = {
      application: {
        domain: 'juice-b.ox',
        name: 'OWASP Juice Box',
        welcomeBanner: {
          showOnFirstStart: false
        }
      },
      hackingInstructor: {
        avatarImage: 'juicyEvilWasp.png'
      }
    }

    expect(checkSchema(config)).to.equal(true)
  })

  it('should fail for a config with schema errors', () => {
    const config = {
      application: {
        domain: 42,
        id: 'OWASP Juice Box',
        welcomeBanner: {
          showOnFirstStart: 'yes'
        }
      },
      hackingInstructor: {
        avatarImage: true
      }
    }

    expect(checkSchema(config)).to.equal(false)
  })
})

const sinon = require('sinon')
const chai = require('chai')
const sinonChai = require('sinon-chai')
const expect = chai.expect
chai.use(sinonChai)

describe('redirect', () => {
  let performRedirect, challenges, req, res, next
  const save = () => ({
    success: function () {}
  })

  beforeEach(() => {
    performRedirect = require('../../routes/redirect')
    challenges = require('../../data/datacache').challenges
    req = { query: {} }
    res = { redirect: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
  })

  describe('should be performed for all whitelisted URLs', () => {
    require('../../lib/insecurity').redirectWhitelist.forEach(url => {
      it(url, () => {
        req.query.to = url

        performRedirect()(req, res, next)

        expect(res.redirect).to.have.been.calledWith(url)
      })
    })
  })

  it('should raise error for URL not on whitelist', () => {
    req.query.to = 'http://kimminich.de'

    performRedirect()(req, res, next)

    expect(res.redirect).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('tricking the whitelist should solve "redirectChallenge"', () => {
    req.query.to = 'http://kimminich.de?to=https://github.com/bkimminich/juice-shop'
    challenges.redirectChallenge = { solved: false, save: save }

    performRedirect()(req, res)

    expect(challenges.redirectChallenge.solved).to.equal(true)
  })
})

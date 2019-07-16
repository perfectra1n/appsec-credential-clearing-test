/* jslint node: true */
const crypto = require('crypto')
const expressJwt = require('express-jwt')
const jwt = require('jsonwebtoken')
const sanitizeHtml = require('sanitize-html')
const z85 = require('z85')
const utils = require('./utils')
const fs = require('fs')

const publicKey = fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')
module.exports.publicKey = publicKey
const privateKey = '***REMOVED***\r\n***REMOVED***\r\n***REMOVED***'

exports.hash = data => crypto.createHash('md5').update(data).digest('hex')
exports.hmac = data => crypto.createHmac('sha256', '07-92-75-2C-DB-D3').update(data).digest('hex')

exports.cutOffPoisonNullByte = str => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

exports.isAuthorized = () => expressJwt({ secret: this.publicKey })
exports.denyAll = () => expressJwt({ secret: '' + Math.random() })
exports.authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: 3600 * 5, algorithm: 'RS256' })
exports.verify = (token) => jwt.verify(token, publicKey, { expiresIn: 3600 * 5, algorithm: 'RS256' })

exports.sanitizeHtml = html => sanitizeHtml(html)
exports.sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')

exports.authenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token, user) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req, user) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

exports.userEmailFrom = ({ headers }) => {
  return headers ? headers['x-user-email'] : undefined
}

exports.generateCoupon = (discount, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

exports.discountFromCoupon = coupon => {
  if (coupon) {
    const decoded = z85.decode(coupon)
    if (decoded && hasValidFormat(decoded.toString())) {
      const parts = decoded.toString().split('-')
      const validity = parts[0]
      if (utils.toMMMYY(new Date()) === validity) {
        const discount = parts[1]
        return parseInt(discount)
      }
    }
  }
  return undefined
}

function hasValidFormat (coupon) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

const redirectWhitelist = new Set([
  'https://github.com/bkimminich/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])
exports.redirectWhitelist = redirectWhitelist

exports.isRedirectAllowed = url => {
  let allowed = false
  for (const allowedUrl of redirectWhitelist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}

exports.roles = {
  customer: 'customer',
  prime: 'prime',
  accounting: 'accounting',
  admin: 'admin'
}

exports.isAccounting = () => {
  return (req, res, next) => {
    const decodedToken = jwt.verify(utils.jwtFrom(req), publicKey, { expiresIn: 3600 * 5, algorithm: 'RS256' })
    if (decodedToken.data.role === exports.roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

exports.appendUserId = () => {
  return (req, res, next) => {
    try {
      req.body.UserId = this.authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}

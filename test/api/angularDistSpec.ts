/*
 * Copyright (c) 2014-2021 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')

const URL = 'http://localhost:3000'

describe('/api', () => {
  it('GET main.js contains Cryptocurrency URLs', () => {
    return frisby.get(URL + '/main.js')
      .expect('status', 200)
      .expect('bodyContains', '/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm')
      .expect('bodyContains', '/redirect?to=https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW')
      .expect('bodyContains', '/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6')
  })

  it('GET main.js contains password hint for support team', () => {
    return frisby.get(URL + '/main.js')
      .expect('status', 200)
      .expect('bodyContains', 'Parola echipei de asistență nu respectă politica corporativă pentru conturile privilegiate! Vă rugăm să schimbați parola &#238;n consecință!')
  })
})

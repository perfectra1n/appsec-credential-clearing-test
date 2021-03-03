/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const challenges = require('../data/datacache').challenges
const fs = require('fs')
const { FileSniffer, asArray } = require('filesniffer')

module.exports = function serveCodeSnippet () {
  return async (req, res, next) => {
    const challenge = challenges[req.params.challenge]
    if (challenge) {
      const matches = await FileSniffer
        .create()
        .path('.')
        .collect(asArray())
        .find(`vuln-code-snippet start ${challenge.key}`)
      if (matches[0]) { // TODO Currently only a single code snippet is supported
        const source = fs.readFileSync(matches[0].path, 'utf8')
        let snippet = source.match(`// vuln-code-snippet start ${challenge.key}(.|\\r\\n)*vuln-code-snippet end ${challenge.key}`)
        snippet = snippet[0]
        snippet = snippet.replace(/\/\/ vuln-code-snippet start.*/g, '')
        snippet = snippet.replace(/\/\/ vuln-code-snippet end.*/g, '')
        snippet = snippet.replace(/.*\/\/ vuln-code-snippet hide-line/g, '')
        snippet = snippet.trim()

        const lines = snippet.split('\r\n')
        let vulnLine
        for (let i = 0; i < lines.length; i++) {
          if (/vuln-code-snippet vuln-line/.exec(lines[i])) {
            vulnLine = i + 1 // TODO Currently only a single vulnerable code line is supported
            break
          }
        }
        snippet = snippet.replace(/\/\/ vuln-code-snippet vuln-line.*/g, '')

        return res.json({ snippet, vulnLine })
      } else {
        res.status(404).json({ status: 'error', error: 'No code snippet available for: ' + challenge.key })
      }
    } else {
      res.status(412).json({ status: 'error', error: 'Unknown challenge key: ' + req.params.challenge })
    }
  }
}

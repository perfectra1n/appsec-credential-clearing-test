/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

import { CodeSnippetService, CodeSnippet } from '../Services/code-snippet.service'
import { CodeFixesService, Fixes } from '../Services/code-fixes.service'
import { VulnLinesService, result } from '../Services/vuln-lines.service'
import { Component, Inject, OnInit } from '@angular/core'

import { MAT_DIALOG_DATA } from '@angular/material/dialog'
import { FormControl } from '@angular/forms'

enum ResultState {
  Undecided,
  Right,
  Wrong,
}

@Component({
  selector: 'app-user-details',
  templateUrl: './code-snippet.component.html',
  styleUrls: ['./code-snippet.component.scss']
})
export class CodeSnippetComponent implements OnInit {
  public snippet: CodeSnippet = null
  public fixes: Fixes = null
  public selectedLines: number[]
  public selectedFix: number
  public tab: FormControl = new FormControl(0)
  public lock: ResultState = ResultState.Undecided
  public result: ResultState = ResultState.Undecided

  constructor (@Inject(MAT_DIALOG_DATA) public dialogData: any, private readonly codeSnippetService: CodeSnippetService, private readonly vulnLinesService: VulnLinesService, private readonly codeFixesService: CodeFixesService) { }

  ngOnInit () {
    this.codeSnippetService.get(this.dialogData.key).subscribe((snippet) => {
      this.snippet = snippet
    }, (err) => {
      this.snippet = { snippet: JSON.stringify(err.error?.error) }
    })
    this.codeFixesService.get(this.dialogData.key).subscribe((fixes) => {
      this.fixes = fixes.fixes
    }, () => {
      this.fixes = null
    })
  }

  addLine = (lines: number[]) => {
    this.selectedLines = lines
  }

  setFix = (fix: number) => {
    this.selectedFix = fix
  }

  toggleTab = (event) => {
    this.tab.setValue(event)
    this.result = ResultState.Undecided
  }

  checkFix = () => {
    this.codeFixesService.check(this.dialogData.key, this.selectedFix).subscribe((verdict) => {
      this.setVerdict(verdict.verdict)
    })
  }

  checkLines = () => {
    this.vulnLinesService.check(this.dialogData.key, this.selectedLines).subscribe((verdict: result) => {
      this.setVerdict(verdict.verdict)
    })
  }

  lockIcon (): string {
    if (this.fixes === null) {
      return 'lock'
    }
    switch (this.lock) {
      case ResultState.Right:
        return 'lock_open'
      case ResultState.Wrong:
        return 'lock'
      case ResultState.Undecided:
        return 'lock'
    }
  }

  setVerdict = (verdict: boolean) => {
    if (verdict) {
      this.result = ResultState.Right
      this.lock = ResultState.Right
      import('../../confetti').then(module => {
        module.shootConfetti()
      })
    } else {
      this.result = ResultState.Wrong
      this.lock = ResultState.Wrong
    }
  }

  resultIcon (): string {
    switch (this.result) {
      case ResultState.Right:
        return 'check'
      case ResultState.Wrong:
        return 'clear'
      default:
        return 'send'
    }
  }
}

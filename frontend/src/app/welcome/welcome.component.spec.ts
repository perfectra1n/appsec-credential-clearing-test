/*
 * Copyright (c) 2014-2020 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { HttpClientTestingModule } from '@angular/common/http/testing'
import { MatDialog, MatDialogModule } from '@angular/material/dialog'
import { CookieService } from 'ngx-cookie-service'

import { async, ComponentFixture, fakeAsync, TestBed, tick } from '@angular/core/testing'

import { WelcomeComponent } from './welcome.component'
import { of } from 'rxjs'
import { ConfigurationService } from '../Services/configuration.service'

describe('WelcomeComponent', () => { // FIXME Tests frequently fail probably due to wrong async handling
  let component: WelcomeComponent
  let configurationService: any
  let cookieService: any
  let fixture: ComponentFixture<WelcomeComponent>
  let dialog: any

  beforeEach(async(() => {
    configurationService = jasmine.createSpyObj('ConfigurationService', ['getApplicationConfiguration'])
    configurationService.getApplicationConfiguration.and.returnValue(of({ application: {} }))
    dialog = jasmine.createSpyObj('MatDialog', ['open'])
    dialog.open.and.returnValue(null)

    TestBed.configureTestingModule({
      imports: [
        TranslateModule.forRoot(),
        HttpClientTestingModule,
        MatDialogModule
      ],
      declarations: [WelcomeComponent],
      providers: [
        { provide: ConfigurationService, useValue: configurationService },
        { provide: MatDialog, useValue: dialog },
        CookieService
      ]
    })
      .compileComponents()

    cookieService = TestBed.inject(CookieService)
  }))

  beforeEach(() => {
    fixture = TestBed.createComponent(WelcomeComponent)
    component = fixture.componentInstance
  })

  it('should create', () => {
    expect(component).toBeTruthy()
  })

  xit('should open the welcome banner dialog if configured to show on start', fakeAsync(() => {
    configurationService.getApplicationConfiguration.and.returnValue(of({ application: { welcomeBanner: { showOnFirstStart: true } } }))
    component.ngOnInit()
    tick()
    expect(dialog.open).toHaveBeenCalled()
  }))

  xit('should not open the welcome banner dialog if configured to not show on start', fakeAsync(() => {
    configurationService.getApplicationConfiguration.and.returnValue(of({ application: { welcomeBanner: { showOnFirstStart: false } } }))
    component.ngOnInit()
    tick()
    expect(dialog.open).not.toHaveBeenCalled()
  }))

  xit('should not open the welcome banner dialog if previously dismissed', fakeAsync(() => {
    configurationService.getApplicationConfiguration.and.returnValue(of({ application: { welcomeBanner: { showOnFirstStart: true } } }))
    cookieService.set('welcomebanner_status', 'dismiss')
    component.ngOnInit()
    tick()
    expect(dialog.open).not.toHaveBeenCalled()
  }))
})

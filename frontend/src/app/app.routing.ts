import { TokenSaleComponent } from './token-sale/token-sale.component'
import { OAuthComponent } from './oauth/oauth.component'
import { BasketComponent } from './basket/basket.component'
import { TrackResultComponent } from './track-result/track-result.component'
import { ContactComponent } from './contact/contact.component'
import { ErasureRequestComponent } from './erasure-request/erasure-request.component'
import { AboutComponent } from './about/about.component'
import { RegisterComponent } from './register/register.component'
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component'
import { SearchResultComponent } from './search-result/search-result.component'
import { LoginComponent } from './login/login.component'
import { AdministrationComponent } from './administration/administration.component'
import { ChangePasswordComponent } from './change-password/change-password.component'
import { ComplaintComponent } from './complaint/complaint.component'
import { TrackOrderComponent } from './track-order/track-order.component'
import { RecycleComponent } from './recycle/recycle.component'
import { ScoreBoardComponent } from './score-board/score-board.component'
import {
  RouterModule,
  Routes,
  UrlMatchResult,
  UrlSegment,
  CanActivate,
  Router
} from '@angular/router'
import { TwoFactorAuthEnterComponent } from './two-factor-auth-enter/two-factor-auth-enter.component'
import { ErrorPageComponent } from './error-page/error-page.component'
import { Injectable } from '@angular/core'
import * as jwt_decode from 'jwt-decode'
import { PrivacySecurityComponent } from './privacy-security/privacy-security.component'
import { TwoFactorAuthComponent } from './two-factor-auth/two-factor-auth.component'
import { DataExportComponent } from './data-export/data-export.component'
import { LastLoginIpComponent } from './last-login-ip/last-login-ip.component'
import { PrivacyPolicyComponent } from './privacy-policy/privacy-policy.component'
import { PaymentComponent } from './payment/payment.component'

export function token1 (...args: number[]) {
  let L = Array.prototype.slice.call(args)
  let D = L.shift()
  return L.reverse().map(function (C, A) {
    return String.fromCharCode(C - D - 45 - A)
  }).join('')
}

export function token2 (...args: number[]) {
  let T = Array.prototype.slice.call(arguments)
  let M = T.shift()
  return T.reverse().map(function (m, H) {
    return String.fromCharCode(m - M - 24 - H)
  }).join('')
}

export const roles = {
  customer: 'customer',
  prime: 'prime',
  accounting: 'accounting',
  admin: 'admin'
}

@Injectable()
export class AdminGuard implements CanActivate {
  constructor (private router: Router) {}

  canActivate () {
    let payload: any
    const token = localStorage.getItem('token')
    if (token) {
      payload = jwt_decode(token)
    }
    if (payload && payload.data && payload.data.role === roles.admin) {
      return true
    } else {
      this.router.navigate(['403'], {
        skipLocationChange: true,
        queryParams: {
          error: 'UNAUTHORIZED_PAGE_ACCESS_ERROR'
        }
      })
      return false
    }
  }
}

const routes: Routes = [
  {
    path: 'administration',
    component: AdministrationComponent,
    canActivate: [AdminGuard]
  },
  {
    path: 'about',
    component: AboutComponent
  },
  {
    path: 'basket',
    component: BasketComponent
  },
  {
    path: 'contact',
    component: ContactComponent
  },
  {
    path: 'complain',
    component: ComplaintComponent
  },
  {
    path: 'payment',
    component: PaymentComponent
  },
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'forgot-password',
    component: ForgotPasswordComponent
  },
  {
    path: 'recycle',
    component: RecycleComponent
  },
  {
    path: 'register',
    component: RegisterComponent
  },
  {
    path: 'search',
    component: SearchResultComponent
  },
  {
    path: 'score-board',
    component: ScoreBoardComponent
  },
  {
    path: 'track-order',
    component: TrackOrderComponent
  },
  {
    path: 'track-result',
    component: TrackResultComponent
  },
  {
    path: '2fa/enter',
    component: TwoFactorAuthEnterComponent
  },
  {
    path: 'privacy-security',
    component: PrivacySecurityComponent,
    children: [
      { path: 'privacy-policy',
        component: PrivacyPolicyComponent
      },
      { path: 'change-password',
        component: ChangePasswordComponent
      },
      {
        path: 'two-factor-authentication',
        component: TwoFactorAuthComponent
      },
      {
        path: 'data-export',
        component: DataExportComponent
      },
      {
        path: 'erasure-request',
        component: ErasureRequestComponent
      },
      {
        path: 'last-login-ip',
        component: LastLoginIpComponent
      }
    ]
  },
  {
    matcher: oauthMatcher,
    data: { params: (window.location.href).substr(window.location.href.indexOf('#')) },
    component: OAuthComponent
  },
  {
    matcher: tokenMatcher,
    component: TokenSaleComponent
  },
  {
    path: '403',
    component: ErrorPageComponent
  },
  {
    path: '**',
    component: SearchResultComponent
  }
]

export const Routing = RouterModule.forRoot(routes, { useHash: true })

export function oauthMatcher (url: UrlSegment[]): UrlMatchResult {
  if (url.length === 0) {
    return null
  }
  let path = window.location.href
  if (path.includes('#access_token=')) {
    return ({ consumed: url })
  }

  return null
}

export function tokenMatcher (url: UrlSegment[]): UrlMatchResult {
  if (url.length === 0) {
    return null
  }

  const path = url[0].toString()
  if (path.match((token1(25, 184, 174, 179, 182, 186) + (36669).toString(36).toLowerCase() + token2(13, 144, 87, 152, 139, 144, 83, 138) + (10).toString(36).toLowerCase()))) {
    return ({ consumed: url })
  }

  return null
}

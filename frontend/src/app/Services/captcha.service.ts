import { HttpClient } from '@angular/common/http';
import { environment } from './../../environments/environment';
import { Injectable } from '@angular/core';
import { catchError } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class CaptchaService {

  private hostServer = environment.hostServer;
  private host = this.hostServer + '/rest/captcha';

  constructor(private http: HttpClient) { }

  getCaptcha () {
    return this.http.get(this.host + '/').pipe(catchError((err) => err));
  }
}

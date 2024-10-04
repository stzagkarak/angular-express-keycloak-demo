import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { environment } from '../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class HttpService {

  constructor(private http: HttpClient) { }

  loginStatus() {
    return this.http.post(environment.BACKEND_HOST + "/login/status", {}, {
      withCredentials: true
    })
  }

  login(isProvider: Boolean) {
    if(!isProvider)
      window.location = (environment.BACKEND_HOST + "/login") as any;
    else {
      window.location = (environment.BACKEND_HOST + "/login?userType=provider") as any;
    }
  }

  register(isProvider: Boolean) {
    if(!isProvider)
      window.location = (environment.BACKEND_HOST + "/register") as any;
    else
      window.location = (environment.BACKEND_HOST + "/register?userType=provider") as any;
  }

  logout() {
    
    window.location = (environment.BACKEND_HOST + "/logout") as any;
  }

  getUserInfo() {
    return this.http.post(environment.BACKEND_HOST + "/user/info", {}, {
      withCredentials: true
    })
  }

  performAdminAction() {
    return this.http.post(environment.BACKEND_HOST + "/admin/task", {}, {
      withCredentials: true
    })
  }

}

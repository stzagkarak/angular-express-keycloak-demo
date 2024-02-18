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

  login() {
    window.location = (environment.BACKEND_HOST + "/login") as any;
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

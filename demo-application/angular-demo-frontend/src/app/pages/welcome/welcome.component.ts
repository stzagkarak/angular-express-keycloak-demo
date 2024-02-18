import { Component } from '@angular/core';
import { HttpService } from '../../http.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-welcome',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './welcome.component.html',
  styleUrl: './welcome.component.css'
})
export class WelcomeComponent {

  constructor(private httpService: HttpService) {}

  loginText="No Info"
  greenOn = false;
  redOn = false;

  userInfo = "No Info";
  redUserInfo = false;

  admActionOutput = "";
  greenAction = false;
  redAction = false;

  checkLoginStatus() {
    this.httpService.loginStatus().subscribe({
      next: (ret:any)=> {
        if(ret.status === 0) {
          this.loginText = "Not Logged In";
          this.greenOn = false;
          this.redOn = true;
        }
        else if(ret.status === 1) {
          this.loginText = "Logged In";
          this.greenOn = true;
          this.redOn = false;
        }
      }
    })
  }

  login() {
    return this.httpService.login()
  }

  logout() {
    return this.httpService.logout()
  }

  getUserInfo() {
    return this.httpService.getUserInfo().subscribe({
      next: (ret)=> {
        this.userInfo = JSON.stringify(ret)
        this.redUserInfo = false;
      },
      error: (err)=> {
        this.userInfo = "Not Authenticated"
        this.redUserInfo = true;
      }
    })
  }

  performAdminAction() {
    return this.httpService.performAdminAction().subscribe({
      next: (ret)=> {
        this.admActionOutput = JSON.stringify(ret);
        this.greenAction = true;
        this.redAction = false;
      },
      error: (err)=> {
        this.admActionOutput = "Not Authenticated"
        this.redAction = true;
        this.greenAction = false;
      }
    })
  }
}
